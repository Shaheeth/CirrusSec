"""Streamlit dashboard. Run: streamlit run dashboard/app.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from ai.analyst import SecurityAnalyst  # noqa: E402
from config.settings import settings  # noqa: E402
from core.models import ScanResult  # noqa: E402
from core.pipeline import run_scan, run_scan_from_text  # noqa: E402
from database.db import Database, diff_scans  # noqa: E402
from ingestion.loader import IngestionError  # noqa: E402
from rag.retriever import Retriever  # noqa: E402
from reports.pdf_report import generate_report  # noqa: E402

st.set_page_config(page_title="CirrusSec", page_icon="assets/cirrussec-icon.png", layout="wide")

# CirrusSec visual theme: restrained artwork, high-contrast content, and solid surfaces.
_BACKGROUND = Path(__file__).resolve().parent.parent / "assets" / "cirrussec-background.jpg"
import base64  # noqa: E402

_bg_rule = "background: #071426;"
if _BACKGROUND.exists():
    _bg64 = base64.b64encode(_BACKGROUND.read_bytes()).decode("ascii")
    _bg_rule = f'background-image: linear-gradient(rgba(5, 16, 34, 0.88), rgba(5, 16, 34, 0.92)), url("data:image/jpeg;base64,{_bg64}"); background-position: center; background-size: cover; background-attachment: fixed;'
st.markdown(
    f"""<style>
    :root {{ color-scheme: dark; }}
    [data-testid="stAppViewContainer"] {{ {_bg_rule} color: #edf6ff; }}
    [data-testid="stHeader"] {{ background: rgba(5, 16, 34, 0.96); }}
    [data-testid="stSidebar"] {{ background: rgba(5, 16, 34, 0.98); border-right: 1px solid #183b5c; }}
    [data-testid="stMainBlockContainer"] {{
        background: rgba(7, 20, 39, 0.94);
        border: 1px solid rgba(83, 184, 230, 0.28);
        border-radius: 18px; padding: 1.5rem 1.7rem 2rem;
        box-shadow: 0 16px 45px rgba(0, 0, 0, 0.22);
    }}
    /* Explicit text colors override Streamlit's theme defaults, which were too dark. */
    [data-testid="stAppViewContainer"], [data-testid="stAppViewContainer"] p,
    [data-testid="stAppViewContainer"] label, [data-testid="stAppViewContainer"] span,
    [data-testid="stAppViewContainer"] li, [data-testid="stAppViewContainer"] small,
    [data-testid="stAppViewContainer"] [data-testid="stCaptionContainer"] {{ color: #d9e8f7; }}
    h1, h2, h3, h4, h5, h6, [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {{
        color: #f4f9ff !important; font-weight: 700; letter-spacing: -0.02em;
        text-shadow: none;
    }}
    [data-testid="stMetric"] {{ background: #0b2340; border: 1px solid #214c70;
        padding: 0.9rem 1rem; border-radius: 13px; }}
    [data-testid="stMetricLabel"] {{ color: #a9c7e2 !important; }}
    [data-testid="stMetricValue"] {{ color: #f4faff !important; font-weight: 700; }}
    [data-testid="stDataFrame"], [data-testid="stTable"] {{
        background: #f8fbff; border-radius: 10px; overflow: hidden;
    }}
    [data-testid="stDataFrame"] *, [data-testid="stTable"] * {{ color: #10243a; }}
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] label {{ color: #d9e8f7 !important; }}
    [data-testid="stSidebar"] img {{ border-radius: 12px; }}
    /* Keep all buttons dark by default and on hover; avoid Streamlit's white default. */
    [data-testid="stButton"] button,
    [data-testid="stDownloadButton"] button,
    [data-testid="stFileUploader"] button {{
        background: #102b47 !important;
        color: #edf7ff !important;
        border: 1px solid #3979a7 !important;
        border-radius: 10px;
        font-weight: 600;
        transition: background-color 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
    }}
    [data-testid="stButton"] button:hover,
    [data-testid="stDownloadButton"] button:hover,
    [data-testid="stFileUploader"] button:hover {{
        background: #174267 !important;
        color: #ffffff !important;
        border-color: #4fc3f7 !important;
        box-shadow: 0 0 0 1px rgba(79, 195, 247, 0.18);
    }}
    [data-testid="stButton"] button:focus-visible,
    [data-testid="stDownloadButton"] button:focus-visible,
    [data-testid="stFileUploader"] button:focus-visible {{
        outline: 2px solid #67d5ff !important;
        outline-offset: 2px;
    }}
    [data-testid="stButton"] button[kind="primary"] {{
        background: #087eae !important; color: #ffffff !important; border-color: #28b8e8 !important;
    }}
    [data-testid="stButton"] button[kind="primary"]:hover {{ background: #09658a !important; }}
    [data-testid="stTextInput"] input, [data-testid="stNumberInput"] input,
    [data-testid="stTextArea"] textarea {{ background: #0b1d33; color: #f4f9ff; border-color: #345773; }}
    [data-testid="stFileUploader"] section {{ background: #0b1d33; border: 1px dashed #3979a7; border-radius: 12px; }}
    [data-testid="stAlert"] {{ border-radius: 10px; }}
    hr {{ border-color: #24445f; }}
    </style>""",
    unsafe_allow_html=True,
)
SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
PAGES = ["Overview", "Cloud Resources", "Security Findings", "Finding Details", "Attack Paths", "IAM Analysis",
         "Activity / Logs", "AI Security Analyst", "Remediation", "Reports"]


@st.cache_resource
def get_db() -> Database:
    return Database(settings.DB_PATH)


@st.cache_resource
def get_retriever() -> Retriever:
    return Retriever(settings.KNOWLEDGE_DIR)


db = get_db()
if "scan" not in st.session_state:
    st.session_state.scan = db.latest_scan()
    if st.session_state.scan is None:
        st.session_state.scan = run_scan()
        db.save_scan(st.session_state.scan)

ROOT_DIR = Path(__file__).resolve().parent.parent
logo_path = ROOT_DIR / "assets" / "Glossy Detective Cloud Security Logo.png"

st.sidebar.image(str(logo_path), width="stretch")
use_container_width=True)
st.sidebar.title("CirrusSec")
page = st.sidebar.radio("Navigate", PAGES)
if st.sidebar.button("🔄 Re-scan NovaTech demo environment"):
    prev = st.session_state.scan
    st.session_state.scan = run_scan()
    db.save_scan(st.session_state.scan)
    st.session_state.last_diff = diff_scans(prev, st.session_state.scan)
upload = st.sidebar.file_uploader("…or scan your own cloud JSON", type=["json"])
if upload is not None and st.sidebar.button("Scan uploaded file"):
    data = upload.getvalue()
    if len(data) > settings.MAX_UPLOAD_BYTES:
        st.sidebar.error("File too large.")
    else:
        try:
            st.session_state.scan = run_scan_from_text(data)
            db.save_scan(st.session_state.scan)
            st.sidebar.success("Scan complete")
        except IngestionError as exc:
            st.sidebar.error(f"Rejected: {exc}")
st.sidebar.caption(f"LLM mode: **{settings.LLM_PROVIDER}**  \nAll data is synthetic.")

scan: ScanResult = st.session_state.scan
analyst = SecurityAnalyst(scan, get_retriever())
counts = scan.counts()


def findings_df(fs):
    return pd.DataFrame([{"ID": f.finding_id, "Severity": f"{SEV_ICON[f.severity.value]} {f.severity.value}", "Risk": f.risk_score,
                          "Title": f.title, "Resource": f.resource_id, "Type": f.resource_type, "Paths": ", ".join(f.attack_path_ids)}
                         for f in fs])


if page == "Overview":
    st.title("Security Overview")
    st.caption(f"Account: {scan.account} · Scan {scan.scan_id} · {scan.scanned_at:%Y-%m-%d %H:%M} UTC")
    c = st.columns(7)
    for col, (label, val) in zip(c, [("Resources", len(scan.resources)), ("Findings", len(scan.findings)),
                                     ("Critical", counts["CRITICAL"]), ("High", counts["HIGH"]), ("Medium", counts["MEDIUM"]),
                                     ("Low", counts["LOW"]), ("Posture score", f"{scan.posture_score}/100")]):
        col.metric(label, val)
    if "last_diff" in st.session_state:
        d = st.session_state.last_diff
        st.info(f"Since previous scan: {len(d['new'])} new, {len(d['resolved'])} resolved, posture change {d['posture_change']:+d}")
    left, right = st.columns(2)
    with left:
        st.subheader("Top risky resources")
        agg = {}
        for f in scan.findings:
            agg.setdefault(f.resource_id, []).append(f.risk_score)
        st.dataframe(pd.DataFrame([{"Resource": k, "Findings": len(v), "Max risk": max(v)} for k, v in
                                   sorted(agg.items(), key=lambda kv: -max(kv[1]))[:6]]), hide_index=True, width="stretch")
        st.subheader("Findings by severity")
        st.bar_chart(pd.Series(counts))
    with right:
        st.subheader("Potential attack paths")
        for p in scan.attack_paths[:4]:
            st.write(f"{SEV_ICON[p.severity.value]} **{p.path_id}** ({p.risk_score}) — " + " → ".join(p.nodes))
        st.subheader("Recent suspicious activity")
        for a in scan.alerts[:5]:
            st.write(f"{SEV_ICON[a.severity.value]} {a.title} — `{a.actor}`")
    st.warning("Facts come from deterministic rules. AI text is an interpretation and must be validated by an analyst.")

elif page == "Cloud Resources":
    st.title("Cloud Resources")
    types = sorted({r.resource_type for r in scan.resources})
    sel = st.multiselect("Type", types, default=types)
    rows = [{"ID": r.resource_id, "Type": r.resource_type,
             "Findings": sum(1 for f in scan.findings if f.resource_id == r.resource_id)} for r in scan.resources if r.resource_type in sel]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    rid = st.selectbox("Inspect resource", [r["ID"] for r in rows])
    st.json(scan.resource(rid).properties)
    st.subheader("Relationships")
    st.dataframe(pd.DataFrame(scan.relationships), hide_index=True, width="stretch")

elif page == "Security Findings":
    st.title("Security Findings")
    sevs = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    st.dataframe(findings_df([f for f in scan.findings if f.severity.value in sevs]), hide_index=True, width="stretch")

elif page == "Finding Details":
    st.title("Finding Details")
    fid = st.selectbox("Finding", [f.finding_id for f in scan.findings])
    f = scan.finding(fid)
    st.subheader(f"{SEV_ICON[f.severity.value]} {f.title}")
    st.write(f"**Severity:** {f.severity.value} · **Risk:** {f.risk_score}/100 ({f.risk_level.value}) · **Confidence:** {f.confidence} · "
             f"**Affected:** `{f.affected_resource}` · **Control:** {f.security_control}")
    st.markdown("#### FACT")
    st.write(f.description)
    st.json(f.evidence, expanded=False)
    st.markdown("#### Why it matters")
    st.write(f.why_it_matters)
    st.markdown("#### Potential impact")
    st.write(f.potential_impact)
    st.markdown("#### Risk score breakdown")
    st.dataframe(pd.DataFrame(f.risk_breakdown), hide_index=True, width="stretch")
    st.markdown("#### Related findings & attack paths")
    st.write(", ".join(f.related_findings) or "None")
    st.write(", ".join(f.attack_path_ids) or "Not on a potential attack path")
    st.markdown("#### MITRE ATT&CK")
    for m in f.mitre:
        st.write(f"**{m.technique_id} {m.technique}** ({m.tactic}) — {m.why_relevant}  \n*Limitation:* {m.limitations}")
    if not f.mitre:
        st.write("No sensible ATT&CK mapping (not forced).")
    st.markdown("#### AI INTERPRETATION")
    r = analyst.explain_finding(f.finding_id)
    st.write(r.interpretation)
    for w in r.warnings:
        st.warning(w)
    st.markdown("#### RECOMMENDATION")
    st.write(f.remediation)
    st.markdown("#### References")
    for ref in f.references:
        st.write(f"- {ref}")

elif page == "Attack Paths":
    st.title("Potential Attack Paths")
    st.caption("Derived from configuration only — these are possible exploitation paths, not evidence of an attack.")
    for p in scan.attack_paths:
        with st.expander(f"{SEV_ICON[p.severity.value]} {p.path_id} · risk {p.risk_score} · " + " → ".join(p.nodes), expanded=p is scan.attack_paths[0]):
            dot = "digraph { rankdir=LR; node [shape=box, style=rounded]; " + " ".join(
                f'"{a}" -> "{b}";' for a, b in zip(p.nodes, p.nodes[1:])) + "}"
            st.graphviz_chart(dot)
            st.write(p.narrative)
            st.write(f"**Impact:** {p.impact}")
            st.write("**Steps:**")
            for step in p.steps:
                st.write(f"- {step}")
            st.write("**Findings creating this path:** " + ", ".join(p.finding_ids))
            if st.button(f"Ask AI to explain {p.path_id}", key=p.path_id):
                r = analyst.explain_path(p.path_id)
                st.info(r.interpretation)
    if not scan.attack_paths:
        st.success("No potential attack paths found.")

elif page == "IAM Analysis":
    st.title("IAM Analysis")
    iam = [r for r in scan.resources if r.resource_type in ("IAMUser", "IAMRole")]
    rows = []
    for r in iam:
        fs = [f.rule_id for f in scan.findings if f.resource_id == r.resource_id]
        rows.append({"Identity": r.resource_id, "Type": r.resource_type, "MFA": str(r.get("mfa_enabled", "n/a")),
                     "Policies": ", ".join(p["name"] for p in r.get("policies", [])), "Findings": ", ".join(fs)})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    for f in [f for f in scan.findings if f.category == "iam"]:
        st.write(f"{SEV_ICON[f.severity.value]} **{f.finding_id}** — {f.description}")
        st.json(f.evidence, expanded=False)

elif page == "Activity / Logs":
    st.title("Cloud Activity Analysis")
    st.caption("Activity analysis looks at what happened. Alerts are indicators needing investigation, not proof of compromise.")
    for a in scan.alerts:
        with st.expander(f"{SEV_ICON[a.severity.value]} {a.alert_id} · {a.title} · {a.actor}"):
            st.write(a.explanation)
            st.write("**Evidence:** " + "; ".join(a.evidence))
            for m in a.mitre:
                st.write(f"**{m.technique_id} {m.technique}** ({m.tactic}) — {m.why_relevant}  \n*Limitation:* {m.limitations}")
    st.subheader("Raw events")
    st.dataframe(pd.DataFrame([{"Time": e.event_time, "Event": e.event_name, "User": e.user, "IP": e.source_ip,
                                "Resource": e.resource, "Error": e.error} for e in scan.events]), hide_index=True, width="stretch")

elif page == "AI Security Analyst":
    st.title("AI Security Analyst")
    st.caption(f"Mode: {settings.LLM_PROVIDER}. Answers use only this scan's data + retrieved knowledge. FACT / AI INTERPRETATION / RECOMMENDATION are separated.")
    examples = ["Summarize the current security posture", "Show me the highest-risk resource", "Explain this attack path",
                "Which finding should I remediate first?", "What could an attacker do if web-server-01 is compromised?",
                "What IAM permission creates this risk?", "Is there suspicious activity?"]
    q = st.selectbox("Example questions", [""] + examples)
    typed = st.text_input("…or ask your own", max_chars=settings.MAX_CHAT_CHARS)
    question = typed or q
    if question:
        r = analyst.chat(question)
        db.save_ai(scan.scan_id, question, r.model_dump_json(), r.mode)
        st.markdown("**FACT** (from deterministic analysis)")
        for fact in r.facts:
            st.write(f"- {fact}")
        st.markdown(f"**AI INTERPRETATION** ({r.mode})")
        st.write(r.interpretation)
        if r.recommendations:
            st.markdown("**RECOMMENDATION**")
            for rec in r.recommendations:
                st.write(f"- {rec}")
        if r.sources:
            st.caption("Knowledge used: " + "; ".join(r.sources))
        for w in r.warnings:
            st.warning(w)

elif page == "Remediation":
    st.title("Remediation Plan")
    ranked = sorted(scan.findings, key=lambda f: f.risk_score + 10 * len(f.attack_path_ids), reverse=True)
    st.caption("Ordered by risk score, with a bonus for findings that sit on attack paths. Test changes in non-production first.")
    for i, f in enumerate(ranked, 1):
        st.write(f"**{i}. {SEV_ICON[f.severity.value]} {f.finding_id}** (risk {f.risk_score}"
                 + (f", on {len(f.attack_path_ids)} path(s)" if f.attack_path_ids else "") + f")  \n{f.remediation}")

elif page == "Reports":
    st.title("Reports")
    if st.button("Generate PDF report"):
        path = generate_report(scan, analyst, settings.REPORT_DIR)
        db.save_report(scan.scan_id, str(path))
        st.session_state.report_path = str(path)
    if "report_path" in st.session_state:
        p = Path(st.session_state.report_path)
        st.success(f"Generated {p.name}")
        st.download_button("Download PDF", p.read_bytes(), file_name=p.name, mime="application/pdf")
    st.subheader("Scan history")
    st.dataframe(pd.DataFrame(db.list_scans()), hide_index=True, width="stretch")
