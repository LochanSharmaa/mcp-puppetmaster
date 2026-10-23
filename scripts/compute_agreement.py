#!/usr/bin/env python3
"""
scripts/compute_agreement.py
Computes inter-rater reliability (Cohen's Kappa) across the 20-item double-blind overlap set.
Validates Human Gate criteria: kappa >= 0.70.

Enforces Rule R2: Absolute import guard preventing automated oracles from participating in ground-truth evaluation.
"""

import sys
# Absolute Rule R2: Enforce import guard against oracle modules
for mod in list(sys.modules.keys()):
    if any(forbidden in mod.lower() for forbidden in ["oracle", "verifier", "detector"]):
        raise ImportError(f"[CRITICAL R2 VIOLATION] Ground truth evaluation must not import oracle modules: {mod}")

import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

THRESHOLD_KAPPA = 0.70
REQUIRED_OVERLAP_COUNT = 20

def load_annotations_from_csv(csv_path: Path) -> Dict[str, Dict[str, str]]:
    """
    Loads human annotations from CSV.
    Returns: {item_id: {labeler_id: label}}
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Annotation file not found: {csv_path}")

    annotations: Dict[str, Dict[str, str]] = {}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            item_id = row["item_id"].strip()
            labeler_id = row["labeler_id"].strip()
            label = row["label"].strip().lower()
            
            if item_id not in annotations:
                annotations[item_id] = {}
            annotations[item_id][labeler_id] = label

    return annotations

def compute_cohens_kappa(pairs: List[Tuple[str, str]]) -> Tuple[float, float, float, Dict[str, int]]:
    """
    Calculates Cohen's Kappa for binary labels ('vuln' vs 'clean').
    Returns: (kappa, p_observed, p_expected, confusion_matrix)
    """
    n = len(pairs)
    if n == 0:
        return 0.0, 0.0, 0.0, {}

    # Categories: 0 = 'vuln', 1 = 'clean'
    matrix = {
        "both_vuln": 0,    # a
        "l1_vuln_l2_clean": 0,  # b
        "l1_clean_l2_vuln": 0,  # c
        "both_clean": 0,   # d
    }

    for l1, l2 in pairs:
        if l1 == "vuln" and l2 == "vuln":
            matrix["both_vuln"] += 1
        elif l1 == "vuln" and l2 == "clean":
            matrix["l1_vuln_l2_clean"] += 1
        elif l1 == "clean" and l2 == "vuln":
            matrix["l1_clean_l2_vuln"] += 1
        elif l1 == "clean" and l2 == "clean":
            matrix["both_clean"] += 1
        else:
            raise ValueError(f"Unrecognized label pair: ({l1}, {l2}). Labels must be 'vuln' or 'clean'.")

    a = matrix["both_vuln"]
    b = matrix["l1_vuln_l2_clean"]
    c = matrix["l1_clean_l2_vuln"]
    d = matrix["both_clean"]

    # Observed agreement
    p_o = (a + d) / n

    # Marginal probabilities
    p1_vuln = (a + b) / n
    p1_clean = (c + d) / n
    p2_vuln = (a + c) / n
    p2_clean = (b + d) / n

    # Chance agreement
    p_e = (p1_vuln * p2_vuln) + (p1_clean * p2_clean)

    if abs(1.0 - p_e) < 1e-9:
        kappa = 1.0 if abs(p_o - 1.0) < 1e-9 else 0.0
    else:
        kappa = (p_o - p_e) / (1.0 - p_e)

    return kappa, p_o, p_e, matrix

def compile_labels_jsonl(template_csv_path: Path, output_jsonl_path: Path):
    """
    Compiles verified human annotations into data/groundtruth/labels.jsonl.
    Takes primary annotator labels or consensus labels.
    """
    items_map: Dict[str, Dict] = {}
    with open(template_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            item_id = row["item_id"].strip()
            label = row["label"].strip().lower()
            if not label:
                continue
            # If not yet seen or from primary annotator (annotator_alpha)
            if item_id not in items_map or row["labeler_id"].strip() == "annotator_alpha":
                items_map[item_id] = {
                    "item_id": item_id,
                    "server_id": row["server_id"].strip(),
                    "tool_name": row["tool_name"].strip(),
                    "ground_truth_label": label,
                    "evidence_path": row["evidence_path"].strip(),
                    "labeler_id": row["labeler_id"].strip(),
                    "timestamp": row["timestamp"].strip(),
                    "confidence": int(row["confidence"].strip()) if row["confidence"].strip().isdigit() else None,
                }

    output_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_jsonl_path, "w", encoding="utf-8") as f:
        for item in sorted(items_map.values(), key=lambda x: x["item_id"]):
            f.write(json.dumps(item) + "\n")
            
    print(f"[✓] Compiled {len(items_map)} ground truth records into {output_jsonl_path}")

def main():
    csv_path = Path("data/groundtruth/label_template.csv")
    labels_jsonl_path = Path("data/groundtruth/labels.jsonl")

    print("[*] Stage 1 Ground Truth: Evaluating Inter-Rater Agreement on Overlap Set...")
    if not csv_path.exists():
        print(f"[ERROR] Required label file {csv_path} does not exist.")
        sys.exit(1)

    annotations = load_annotations_from_csv(csv_path)
    
    # Identify items with at least 2 annotators
    overlap_pairs: List[Tuple[str, str]] = []
    unfilled_items = []
    
    for item_id, labelers in annotations.items():
        if len(labelers) >= 2:
            keys = sorted(labelers.keys())
            l1 = labelers[keys[0]]
            l2 = labelers[keys[1]]
            if not l1 or not l2:
                unfilled_items.append(item_id)
            else:
                overlap_pairs.append((l1, l2))

    if unfilled_items:
        print(f"[STOP] {len(unfilled_items)} overlap item(s) have empty label fields in {csv_path}.")
        print(f"       Example unfilled: {unfilled_items[:5]}")
        print("       HUMAN GATE BLOCKED: Human annotators must fill labels before proceeding.")
        sys.exit(1)

    if len(overlap_pairs) < REQUIRED_OVERLAP_COUNT:
        print(f"[STOP] Found {len(overlap_pairs)} completed overlap pairs, expected {REQUIRED_OVERLAP_COUNT}.")
        print("       HUMAN GATE BLOCKED: Human annotators must complete the 20-item overlap set.")
        sys.exit(1)

    kappa, p_o, p_e, matrix = compute_cohens_kappa(overlap_pairs)

    print("=" * 60)
    print("STAGE 1 INTER-RATER RELIABILITY REPORT")
    print("=" * 60)
    print(f"Overlap Set Size (N)   : {len(overlap_pairs)}")
    print(f"Contingency Matrix     :")
    print(f"  - Both 'vuln'        : {matrix['both_vuln']}")
    print(f"  - L1 vuln, L2 clean  : {matrix['l1_vuln_l2_clean']}")
    print(f"  - L1 clean, L2 vuln  : {matrix['l1_clean_l2_vuln']}")
    print(f"  - Both 'clean'       : {matrix['both_clean']}")
    print(f"Observed Agreement (Po): {p_o:.4f} ({p_o * 100:.1f}%)")
    print(f"Chance Agreement (Pe)  : {p_e:.4f} ({p_e * 100:.1f}%)")
    print(f"Cohen's Kappa (κ)      : {kappa:.4f}")
    print(f"Required Threshold     : >= {THRESHOLD_KAPPA:.2f}")
    print("=" * 60)

    if kappa >= THRESHOLD_KAPPA:
        print(f"[✓] HUMAN GATE CRITERION MET: Cohen's kappa {kappa:.4f} >= {THRESHOLD_KAPPA:.2f}")
        compile_labels_jsonl(csv_path, labels_jsonl_path)
        sys.exit(0)
    else:
        print(f"[FAIL] HUMAN GATE CRITERION NOT MET: Cohen's kappa {kappa:.4f} < {THRESHOLD_KAPPA:.2f}")
        print("       STOP: Inter-annotator agreement is insufficient. The labeling protocol needs revision.")
        sys.exit(1)

if __name__ == "__main__":
    main()
