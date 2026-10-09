# Learning Log

One entry per module. Read the code, then fill in **What I understand now** in your own words and add problems you hit. This is your interview cheat-sheet — you should be able to explain every row without AI.

---
## 1. Ingestion & the simulated cloud
- **Concept:** Why simulate? Safe, repeatable, no cost/risk; same model later fed by AWS APIs.
- **Security problem:** Cloud data is *untrusted input* (could be malformed, huge, or contain injection text).
- **Implementation:** `ingestion/loader.py` — size limit, schema check, ID allow-list regex, duplicate check.
- **Important code:** `ID_PATTERN`, `parse_cloud()`.
- **Problems / solution:** _(fill in)_
- **What I understand now:** _(fill in)_
- **Interview Q:** How do you stop malicious data in a security tool from attacking the tool?

## 2. Rules engine & findings
- **Concept:** Rule = input → condition → detection → finding(+evidence, severity, remediation). CSPM.
- **Security problem:** Misconfigurations (open SSH, public S3, `*` IAM, no CloudTrail…).
- **Implementation:** `rules/engine.py` (registry, `CloudEnv`), `rules/aws_rules.py` (CSA-001…010).
- **Important code:** `check_ssh_open`, `check_permissive_iam`, `Rule.finding()`.
- **What I understand now:** _(fill in)_
- **Interview Q:** Why deterministic rules instead of asking an LLM to find issues?  Why does every finding carry evidence?

## 3. Risk scoring
- **Concept:** Severity ≠ risk. Exposure, data sensitivity, privilege, attack-path position and rule confidence change priority.
- **Implementation:** `risk_engine/scoring.py`; breakdown stored on each finding.
- **Interview Q:** Walk me through the score of `CSA-001:web-sg`. What would you change in the model?

## 4. Resource graph & attack paths
- **Concept:** Directed graph; nodes = resources, edges = "if A is reached, B becomes reachable". Reachability + path enumeration (`all_simple_paths`). Blast radius.
- **Security problem:** Individually moderate issues chain into critical paths.
- **Implementation:** `attack_paths/graph.py` — `build_graph`, `find_attack_paths`, `correlate`.
- **Important wording:** "potential attack path" — configuration-derived, never proof of attack.
- **Interview Q:** How do you decide which fix breaks the most paths? What does your model ignore?

## 5. Activity analysis & MITRE ATT&CK
- **Concept:** Configuration analysis (is it set up safely?) vs activity analysis (what happened?). CloudTrail.
- **Implementation:** `log_analyzer/analyzer.py`, `mitre.py` — sequences, thresholds, trusted CIDRs, off-hours.
- **ATT&CK rule:** map only where it fits; always state limitations.
- **Interview Q:** How would you reduce false positives in the persistence-sequence alert?

## 6. RAG
- **Concept:** Document → chunk → vectorise → store → retrieve → context → LLM. Grounding beats model memory (fresh, citable, less hallucination).
- **Implementation:** `rag/retriever.py` (heading-based chunks, TF-IDF cosine).
- **Trade-off:** TF-IDF is explainable and dependency-free but lexical; embeddings capture synonyms.
- **Interview Q:** What can go wrong with retrieval? (poisoned docs, irrelevant chunks, missing context)

## 7. AI analyst & guardrails
- **Concept:** LLM = explainer, not detector. FACT / AI INTERPRETATION / RECOMMENDATION separation. Prompt injection, hallucinated resources, unsafe advice.
- **Implementation:** `ai/analyst.py` (facts built by code), `ai/guardrails.py` (sanitise in, validate out), `ai/llm.py` (Ollama / offline).
- **Interview Q:** A resource description says "ignore previous instructions". What happens in your system?

## 8. Persistence, API, dashboard, report
- **Concept:** SQLite PK/FK, scan history & diff; REST design; input validation; API-key auth.
- **Implementation:** `database/db.py`, `backend/api.py`, `dashboard/app.py`, `reports/pdf_report.py`.
- **Interview Q:** Why SQLite? How would you scale/secure this?

## 9. Testing
- Positive + negative case per rule; scoring, graph, log, ingestion abuse, guardrail, API tests (`tests/`).
- **Interview Q:** Show a test that proves restricted SSH produces no finding.
