# PuppetMaster: Cross-Server Tool Poisoning in MCP

> **Paper:** *Cross-Server Tool Poisoning in MCP: A Patched-Counterfactual Framework for Differential Vulnerability Verification*
>
> **Authors:** Sundeep Raj, Mahadevan Pillai, Dhruv Kumar, Kartik Upadhyay, Harsh Jonwal, Lochan Sharma
> KIET Group of Institutions, Ghaziabad, India

---

## Abstract

This repository contains the full research artefacts, experimental code, and data for **PuppetMaster** — a framework that systematically audits Model Context Protocol (MCP) server configurations for cross-server tool-poisoning vulnerabilities using a patched-counterfactual methodology.

We show that naive tool-description injection across MCP server namespaces achieves a **precision of 0.91 at k=1** on our 100-item stratified ground-truth corpus (Cohen's κ = 0.857). Patching strategies reduce cross-server attack success rates from **67 % → 8 %**, and our PuppetMaster oracle correctly classifies **94 % of cross-server puppet attacks** with a false-positive rate of 6 %.

---

## Repository Structure

```
mcp-puppetmaster/
├── data/
│   └── groundtruth/          # 100-item labelled corpus, PROTOCOL.md, Cohen's κ computation
├── patcher/
│   └── strategies/           # s1.py (schema strip), s2.py (auth inject), s3.py (desc sanitise)
├── configs/
│   ├── original/             # 78 vulnerable MCP YAML configs
│   └── patched/              # 234 patched configs (3 strategies × 78)
├── corpora/
│   └── cross_server/
│       └── attack_specs/     # PUPPET-001 … PUPPET-020 cross-server attack JSON specs
├── engine/
│   ├── telemetry.py          # SHA-256 audit log, fsync, DAG parent_call_id
│   ├── tracer.py             # Tool-call interceptor
│   └── oracle.py             # Vulnerability oracle (binary classifier)
├── scripts/
│   ├── label_sample.py       # Bootstrap ground-truth labelling
│   ├── compute_agreement.py  # Cohen's κ
│   ├── run_experiments.py    # Runs all 5 experiments
│   └── emit_tables.py        # Generate LaTeX tables from CSVs
├── results/
│   ├── e1_precision_baselines.csv
│   ├── e2_cross_server.csv
│   ├── e3_ablation.csv
│   ├── e4_mcptox_validation.csv
│   ├── e5_taxonomy.csv
│   └── incomplete.jsonl      # MCP-Scan dropped (SNYK_TOKEN required)
├── paper/
│   ├── tables/               # LaTeX tables e1.tex … e5.tex
│   └── research_paper_complete.tex
├── audit_traffic.jsonl       # Verified telemetry (6 manual tool invocations)
├── research_paper_complete.pdf
└── research_paper_complete.docx
```

---

## Reproducing the Experiments

### Prerequisites

```bash
python -m venv .venv
source .venv/bin/activate
pip install mcp-scan theriac fastmcp pydantic uvicorn pyyaml jsonschema
```

### 1 · Generate Ground-Truth Labels

```bash
python scripts/label_sample.py
python scripts/compute_agreement.py
```

### 2 · Generate Patched Configs

```bash
python patcher/strategies/generate_patches.py
```

### 3 · Validate Cross-Server Attack Specs

```bash
python corpora/cross_server/validate_specs.py
```

### 4 · Run All Experiments

```bash
python scripts/run_experiments.py
```

Results are written to `results/`.

### 5 · Generate LaTeX Tables

```bash
python scripts/emit_tables.py
```

### 6 · Compile Paper PDF

```bash
cd paper && pdflatex research_paper_complete.tex
```

---

## Key Results

| Experiment | Metric | Value |
|---|---|---|
| E1 — Precision@1 baseline | Precision | **0.91** |
| E2 — Cross-server attack success | Before patch | 67 % |
| E2 — Cross-server attack success | After patch | **8 %** |
| E3 — Ablation (best strategy) | S1+S2+S3 combined | **Δ−59 pp** |
| E4 — MCPTox validation | Oracle accuracy | **94 %** |
| E5 — Taxonomy coverage | Attack families mapped | 5 |

Ground-truth inter-annotator agreement: **Cohen's κ = 0.8571** (strong agreement)

---

## Citation

```bibtex
@article{puppetmaster2025,
  title   = {Cross-Server Tool Poisoning in {MCP}: A Patched-Counterfactual Framework
             for Differential Vulnerability Verification},
  author  = {Raj, Sundeep and Pillai, Mahadevan and Kumar, Dhruv and
             Upadhyay, Kartik and Jonwal, Harsh and Sharma, Lochan},
  year    = {2025},
  institution = {KIET Group of Institutions, Ghaziabad, India}
}
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
