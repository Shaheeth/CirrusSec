"""Professional PDF security report (ReportLab)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ai.analyst import SecurityAnalyst
from core.models import Finding, ScanResult, Severity

SEV_COLOR = {"CRITICAL": "#b71c1c", "HIGH": "#e65100", "MEDIUM": "#f9a825", "LOW": "#2e7d32"}
_ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10, textColor=colors.HexColor("#555555"))
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], textColor=colors.HexColor("#0d2b45"), spaceBefore=10)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], textColor=colors.HexColor("#0d2b45"))
LABEL = {"fact": "FACT", "ai": "AI INTERPRETATION", "rec": "RECOMMENDATION"}


def _p(text: str, style=BODY) -> Paragraph:
    return Paragraph(escape(str(text)).replace("`", ""), style)


def _tag(kind: str, text: str) -> Paragraph:
    return Paragraph(f"<b>[{LABEL[kind]}]</b> " + escape(str(text)).replace("`", ""), BODY)


def _table(rows, widths, header=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d0d8")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("FONTSIZE", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d2b45")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(style))
    return t


def _finding_block(f: Finding) -> list:
    sev = f.severity.value
    out = [Paragraph(f'<font color="{SEV_COLOR[sev]}"><b>[{sev}]</b></font> {escape(f.title)} — {escape(f.resource_id)} '
                     f'(risk {f.risk_score}/100)', H2),
           _tag("fact", f.description), _tag("fact", f"Evidence: {_short(f.evidence)}"),
           _p(f"Why it matters: {f.why_it_matters}"), _p(f"Potential impact: {f.potential_impact}")]
    if f.mitre:
        m = f.mitre[0]
        out.append(_p(f"MITRE ATT&CK: {m.technique_id} {m.technique} ({m.tactic}). Limitation: {m.limitations}", SMALL))
    out += [_tag("rec", f.remediation), Spacer(1, 4)]
    return out


def _short(d, n=260) -> str:
    s = str(d)
    return s if len(s) <= n else s[:n] + "…"


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.grey)
    canvas.drawString(18 * mm, 10 * mm, "AI Cloud Security Analyst — synthetic/lab data — Confidential")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_report(scan: ScanResult, analyst: SecurityAnalyst, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"security_report_{scan.scan_id}.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"Cloud Security Report - {scan.account}")
    s: list = []
    c = scan.counts()

    s += [Spacer(1, 40 * mm), Paragraph("Cloud Security Assessment Report", ParagraphStyle("t", parent=_ss["Title"], textColor=colors.HexColor("#0d2b45"))),
          Paragraph(escape(scan.account), _ss["Heading2"]),
          _p(f"Scan ID {scan.scan_id} · Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} · Prepared by AI Cloud Security Analyst"),
          Spacer(1, 8), _p("Facts in this report come from deterministic rules over the provided configuration. "
                           "Sections labelled AI INTERPRETATION are model/template-written explanations and must be validated by an analyst. "
                           "Attack paths are potential paths, not evidence of compromise."), PageBreak()]

    # 1 Executive summary
    summary = analyst.investigation_summary()
    s += [Paragraph("1. Executive Summary", H1),
          _tag("fact", f"{len(scan.resources)} resources scanned; {len(scan.findings)} findings; {len(scan.attack_paths)} potential attack paths; "
                       f"{len(scan.alerts)} activity alerts. Posture score {scan.posture_score}/100."),
          _tag("ai", summary.interpretation)]
    for r in summary.recommendations[:3]:
        s.append(_tag("rec", r))

    # 2 Posture
    s += [Paragraph("2. Security Posture", H1),
          _table([["Severity", "Findings"]] + [[k, str(v)] for k, v in reversed(list(c.items()))], [60 * mm, 30 * mm]),
          Spacer(1, 6), _p("Score = 100 − Σ(finding risk / 15). Risk = severity base + exposure + data sensitivity + privileges + attack-path position, scaled by rule confidence.", SMALL)]

    # 3-5 Findings by severity
    for n, sev in enumerate((Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM), 3):
        s.append(Paragraph(f"{n}. {sev.value.title()} Findings", H1))
        fs = [f for f in scan.findings if f.severity == sev]
        if not fs:
            s.append(_p("No findings at this severity."))
        for f in fs:
            s += _finding_block(f)

    # 6 Affected resources
    s.append(Paragraph("6. Affected Resources", H1))
    by_res: dict[str, list[Finding]] = {}
    for f in scan.findings:
        by_res.setdefault(f.resource_id, []).append(f)
    rows = [["Resource", "Type", "Findings", "Max risk"]] + [
        [rid, fl[0].resource_type, ", ".join(x.rule_id for x in fl), str(max(x.risk_score for x in fl))]
        for rid, fl in sorted(by_res.items(), key=lambda kv: -max(x.risk_score for x in kv[1]))]
    s.append(_table(rows, [45 * mm, 30 * mm, 70 * mm, 20 * mm]))

    # 7 Attack paths
    s.append(Paragraph("7. Potential Attack Paths", H1))
    for p in scan.attack_paths:
        s += [Paragraph(f'<font color="{SEV_COLOR[p.severity.value]}"><b>{p.path_id} [{p.severity.value}]</b></font> '
                        + escape(" → ".join(p.nodes)) + f" (risk {p.risk_score})", H2),
              _tag("fact", f"Findings enabling this path: {', '.join(p.finding_ids)}"), _p(p.narrative), _p(f"Potential impact: {p.impact}")]
        for step in p.steps:
            s.append(_p("• " + step, SMALL))
    if not scan.attack_paths:
        s.append(_p("No potential attack paths were identified."))

    # 8 Activity
    s.append(Paragraph("8. Cloud Activity Analysis", H1))
    s.append(_p("Activity alerts are indicators requiring investigation, not proof of compromise."))
    rows = [["ID", "Severity", "Actor / IP", "Alert"]] + [[a.alert_id, a.severity.value, f"{a.actor}\n{a.source_ip}", _p(a.title, SMALL)] for a in scan.alerts]
    s.append(_table(rows, [18 * mm, 22 * mm, 42 * mm, 83 * mm]) if scan.alerts else _p("No suspicious activity detected in provided logs."))

    # 9 MITRE
    s.append(Paragraph("9. MITRE ATT&amp;CK Mapping", H1))
    seen, rows = set(), [["Technique", "Tactic", "Source", "Limitation"]]
    for f in scan.findings:
        for m in f.mitre:
            if (m.technique_id, f.finding_id) not in seen:
                seen.add((m.technique_id, f.finding_id))
                rows.append([f"{m.technique_id} {m.technique}", m.tactic, f.finding_id, m.limitations])
    for a in scan.alerts:
        for m in a.mitre:
            if (m.technique_id, a.alert_id) not in seen:
                seen.add((m.technique_id, a.alert_id))
                rows.append([f"{m.technique_id} {m.technique}", m.tactic, a.alert_id, m.limitations])
    wrap = ParagraphStyle("w", parent=SMALL, textColor=colors.black)
    s.append(_table([[Paragraph(escape(str(x)), wrap) if i else x for x in r] for i, r in enumerate(rows)],
                    [48 * mm, 30 * mm, 30 * mm, 57 * mm]))

    # 10 Risk analysis
    s.append(Paragraph("10. Risk Analysis", H1))
    rows = [["Finding", "Score", "Breakdown"]] + [
        [f.finding_id, str(f.risk_score), " + ".join(f"{b['points']} {b['factor']}" for b in f.risk_breakdown if b["points"])]
        for f in scan.findings[:12]]
    s.append(_table([[Paragraph(escape(str(x)), wrap) if i else x for x in r] for i, r in enumerate(rows)], [55 * mm, 15 * mm, 95 * mm]))

    # 11 Remediation
    s.append(Paragraph("11. Remediation Recommendations", H1))
    plan = analyst.chat("Give me a remediation plan")
    s.append(_tag("ai", plan.interpretation))
    for f in sorted(scan.findings, key=lambda f: f.risk_score + 10 * len(f.attack_path_ids), reverse=True)[:8]:
        s.append(_tag("rec", f"{f.finding_id}: {f.remediation}"))

    # 12 AI summary
    s += [Paragraph("12. AI-generated Investigation Summary", H1), _p(f"Generation mode: {summary.mode}. Review before relying on it.", SMALL)]
    for fact in summary.facts[:5]:
        s.append(_tag("fact", fact))
    s.append(_tag("ai", summary.interpretation))
    if summary.sources:
        s.append(_p("Knowledge sources: " + "; ".join(summary.sources), SMALL))

    # Appendix
    s += [Paragraph("Appendix: Scope and Method", H1),
          _p("Data: simulated/synthetic resource configuration and CloudTrail-style events. Rules: CSA-001…CSA-010 (see docs). "
             "Limitations: no IAM condition/SCP/permission-boundary evaluation, no vulnerability scanning, no runtime telemetry, "
             "simplified reachability model. CIS references are approximate pointers."),
          _p("Resources scanned: " + ", ".join(r.resource_id for r in scan.resources), SMALL)]
    doc.build(s, onFirstPage=_footer, onLaterPages=_footer)
    return path
