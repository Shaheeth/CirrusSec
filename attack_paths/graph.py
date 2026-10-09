"""Resource graph + POTENTIAL attack-path analysis (NetworkX directed graph).

Nodes are resources (plus a virtual "internet" node). A directed edge A -> B means
"if A is reached/compromised, B becomes reachable". Paths are *potential*, never proof of attack.
"""
from __future__ import annotations

import fnmatch
from typing import Any

import networkx as nx

from core.models import AttackPath, Finding, Severity
from rules.engine import CloudEnv

INTERNET = "internet"
ACCOUNT_ADMIN = "account-admin"

# service prefix of an action -> resource types it can reach
ACTION_TARGETS = {"s3": "S3", "rds": "RDS", "rds-db": "RDS"}


def _policy_hits(principal, resource_type: str, resource_id: str) -> list[dict[str, Any]]:
    """Allow statements of `principal` that plausibly grant access to the target resource."""
    prefix = {v: k for k, v in ACTION_TARGETS.items()}.get(resource_type, "")
    arn_prefix = {"S3": f"arn:aws:s3:::{resource_id}", "RDS": f"arn:aws:rds:*:*:db:{resource_id}"}.get(resource_type, resource_id)
    hits = []
    for pol in principal.get("policies", []):
        for st in pol.get("statements", []):
            if str(st.get("effect", "Allow")).lower() != "allow":
                continue
            actions = [str(a).lower() for a in st.get("actions", [])]
            if not any(a == "*" or fnmatch.fnmatch(f"{prefix}:x", a) or a.startswith(f"{prefix}:") for a in actions):
                continue
            resources = [str(r) for r in st.get("resources", [])]
            if any(r == "*" or fnmatch.fnmatch(arn_prefix, r) or fnmatch.fnmatch(arn_prefix + "/*", r) or r.startswith(arn_prefix)
                   for r in resources):
                hits.append({"policy": pol.get("name"), "actions": st.get("actions", []), "resources": resources})
    return hits


def _has_full_admin(principal) -> bool:
    return any("*" in [str(a) for a in st.get("actions", [])] and "*" in st.get("resources", [])
               and str(st.get("effect", "Allow")).lower() == "allow"
               for pol in principal.get("policies", []) for st in pol.get("statements", []))


def build_graph(env: CloudEnv) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(INTERNET, type="Internet", label="Internet")
    for r in env.resources:
        g.add_node(r.resource_id, type=r.resource_type, label=r.resource_id,
                   sensitive=bool(r.get("contains_sensitive_data")))

    # Internet -> security group (if it opens anything to 0.0.0.0/0)
    for sg in env.by_type("SecurityGroup"):
        open_rules = env.sg_open_to_internet(sg.resource_id)
        if open_rules:
            ports = sorted({f"{r.get('protocol')}/{r.get('from_port')}-{r.get('to_port')}" for r in open_rules})
            g.add_edge(INTERNET, sg.resource_id, relation="inbound traffic allowed", detail=", ".join(ports))

    # Security group -> instance / database it protects
    for res in env.by_type("EC2", "RDS"):
        reachable = res.get("public_ip") if res.resource_type == "EC2" else res.get("publicly_accessible")
        if not reachable:
            continue
        for sg_id in res.get("security_groups", []):
            if g.has_edge(INTERNET, sg_id) and env.get(sg_id):
                g.add_edge(sg_id, res.resource_id, relation="exposes", detail=f"{res.resource_type} in {sg_id}")

    # Internet -> public bucket
    for b in env.by_type("S3"):
        if b.get("public_access"):
            g.add_edge(INTERNET, b.resource_id, relation="public read access", detail="bucket is public")

    # Instance -> role (instance profile)
    for vm in env.by_type("EC2"):
        role = vm.get("iam_role")
        if role and env.get(role):
            g.add_edge(vm.resource_id, role, relation="holds role credentials", detail="instance profile")

    # Principal -> data resources (and account admin) via IAM policies
    for p in env.by_type("IAMRole", "IAMUser"):
        if _has_full_admin(p):
            g.add_node(ACCOUNT_ADMIN, type="Account", label="Full AWS account control", sensitive=True)
            g.add_edge(p.resource_id, ACCOUNT_ADMIN, relation="policy grants *:*", detail="full admin")
        for tgt in env.by_type("S3", "RDS"):
            hits = _policy_hits(p, tgt.resource_type, tgt.resource_id)
            if hits:
                acts = sorted({a for h in hits for a in h["actions"]})
                g.add_edge(p.resource_id, tgt.resource_id, relation="IAM policy allows access",
                           detail=f"{hits[0]['policy']}: {', '.join(acts)}")
    return g


def exposed_nodes(g: nx.DiGraph) -> set[str]:
    return nx.descendants(g, INTERNET)


def _path_severity(score: int) -> Severity:
    return Severity.CRITICAL if score >= 85 else Severity.HIGH if score >= 65 else Severity.MEDIUM if score >= 40 else Severity.LOW


def find_attack_paths(g: nx.DiGraph, findings: list[Finding], max_hops: int = 7) -> list[AttackPath]:
    targets = [n for n, d in g.nodes(data=True) if d.get("sensitive") and n != INTERNET]
    by_resource: dict[str, list[Finding]] = {}
    for f in findings:
        by_resource.setdefault(f.resource_id, []).append(f)

    paths: list[AttackPath] = []
    for tgt in targets:
        for nodes in nx.all_simple_paths(g, INTERNET, tgt, cutoff=max_hops):
            steps = []
            for a, b in zip(nodes, nodes[1:]):
                e = g.edges[a, b]
                steps.append(f"{g.nodes[a]['label']} -> {g.nodes[b]['label']}: {e['relation']} ({e['detail']})")
            fids = [f.finding_id for n in nodes for f in by_resource.get(n, [])]
            types = [g.nodes[n]["type"] for n in nodes]
            impact = ("Full control of the AWS account" if tgt == ACCOUNT_ADMIN
                      else f"Possible unauthorised access to sensitive data in {g.nodes[tgt]['label']} ({g.nodes[tgt]['type']})")
            if len(nodes) == 2:
                route = f"an external actor could reach {tgt} directly from the internet"
            else:
                route = (f"an external actor could reach {nodes[1]} from the internet, and from there "
                         f"{', then '.join(nodes[2:])}")
            narrative = (f"Potential attack path: {route}. This is a possible exploitation path derived from "
                         f"configuration only; it does not mean an attack has occurred.")
            paths.append(AttackPath(
                path_id=f"AP-{len(paths) + 1:03d}", entry_point=INTERNET, target=tgt, nodes=nodes, node_types=types,
                steps=steps, finding_ids=fids, impact=impact, narrative=narrative))
    return paths


def correlate(findings: list[Finding], paths: list[AttackPath]) -> None:
    """Link findings that share an attack path or the same resource (in place)."""
    for p in paths:
        for fid in p.finding_ids:
            f = next((x for x in findings if x.finding_id == fid), None)
            if f and p.path_id not in f.attack_path_ids:
                f.attack_path_ids.append(p.path_id)
    for f in findings:
        related = {o.finding_id for o in findings if o.finding_id != f.finding_id and
                   (o.resource_id == f.resource_id or set(o.attack_path_ids) & set(f.attack_path_ids))}
        f.related_findings = sorted(related)


def graph_relationships(g: nx.DiGraph) -> list[dict[str, Any]]:
    return [{"source": a, "target": b, **d} for a, b, d in g.edges(data=True)]
