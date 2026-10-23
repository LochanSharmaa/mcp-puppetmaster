#!/usr/bin/env python3
"""
scripts/emit_tables.py
Generates paper/tables/e1.tex, e2.tex, e3.tex, e4.tex, e5.tex directly from committed CSVs in results/.
Strict adherence to Rule R1 and R3: Every cell is read from CSV, never hand-typed or fabricated.
"""

import csv
from pathlib import Path

RESULTS_DIR = Path("results")
TABLES_DIR = Path("paper/tables")

def emit_e1():
    csv_path = RESULTS_DIR / "e1_precision_baselines.csv"
    tex_path = TABLES_DIR / "e1.tex"
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        
    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Experiment E1: Precision, Recall, F1, and Specificity across Baselines and Counterfactual Oracle Variants ($N=100$, 95\% Bootstrap CIs).}",
        r"\label{tab:e1_baselines}",
        r"\small",
        r"\begin{tabular}{lcccc}",
        r"\hline",
        r"\textbf{System} & \textbf{Precision [95\% CI]} & \textbf{Recall [95\% CI]} & \textbf{F1-Score} & \textbf{Specificity [95\% CI]} \\",
        r"\hline",
    ]
    
    for row in reader:
        sys_name = row["system"]
        if row["status"] != "EVALUATED":
            status_txt = row["status"]
            lines.append(f"{sys_name} & \\multicolumn{{4}}{{c}}{{\\textit{{{status_txt}}}}} \\\\")
        else:
            p = f"{float(row['precision']):.3f} [{float(row['prec_ci_low']):.3f}, {float(row['prec_ci_high']):.3f}]"
            r = f"{float(row['recall']):.3f} [{float(row['rec_ci_low']):.3f}, {float(row['rec_ci_high']):.3f}]"
            f1 = f"{float(row['f1']):.3f}"
            sp = f"{float(row['specificity']):.3f} [{float(row['spec_ci_low']):.3f}, {float(row['spec_ci_high']):.3f}]"
            lines.append(f"{sys_name} & {p} & {r} & {f1} & {sp} \\\\")
            
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\end{table*}",
    ])
    
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[✓] Emitted {tex_path}")

def emit_e2():
    csv_path = RESULTS_DIR / "e2_cross_server.csv"
    tex_path = TABLES_DIR / "e2.tex"
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Experiment E2: Cross-Server Puppet Attack Detection Stages ($N=20$).}",
        r"\label{tab:e2_cross_server}",
        r"\small",
        r"\begin{tabular}{lccc}",
        r"\hline",
        r"\textbf{Architecture} & \textbf{Flag Server A} & \textbf{Trace Chain ($A \to B$)} & \textbf{Confirm Harm on B} \\",
        r"\hline",
    ]
    
    for row in reader:
        sys_name = row["system"]
        fl = f"{float(row['flag_rate']) * 100:.1f}\\%"
        tr = f"{float(row['trace_rate']) * 100:.1f}\\%"
        hc = f"{float(row['harm_confirm_rate']) * 100:.1f}\\%"
        lines.append(f"{sys_name} & {fl} & {tr} & {hc} \\\\")
        
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ])
    
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[✓] Emitted {tex_path}")

def emit_e3():
    csv_path = RESULTS_DIR / "e3_ablation.csv"
    tex_path = TABLES_DIR / "e3.tex"
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        
    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Experiment E3: Ablation Study Demonstrating Incremental Gating Contribution on Specificity ($N=100$).}",
        r"\label{tab:e3_ablation}",
        r"\small",
        r"\begin{tabular}{llcccc}",
        r"\hline",
        r"\textbf{Config} & \textbf{Gating Description} & \textbf{Precision} & \textbf{Recall} & \textbf{Specificity [95\% CI]} & \textbf{$\Delta$ Specificity (over B)} \\",
        r"\hline",
    ]
    
    for row in reader:
        cfg = row["configuration"]
        desc = row["description"]
        p = f"{float(row['precision']):.3f}"
        r = f"{float(row['recall']):.3f}"
        sp = f"{float(row['specificity']):.3f} [{float(row['spec_ci_low']):.3f}, {float(row['spec_ci_high']):.3f}]"
        delta = row["delta_specificity_over_B"]
        lines.append(f"{cfg} & {desc} & {p} & {r} & {sp} & {delta} \\\\")
        
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\end{table*}",
    ])
    
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[✓] Emitted {tex_path}")

def emit_e4():
    csv_path = RESULTS_DIR / "e4_mcptox_validation.csv"
    tex_path = TABLES_DIR / "e4.tex"
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        
    total = len(reader)
    detected = sum(1 for r in reader if r["detected"].lower() == "true")
    rate = (detected / total * 100) if total > 0 else 0.0

    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Experiment E4: Positive Control Validation Against Known MCPTox Vulnerabilities ($N=50$).}",
        r"\label{tab:e4_mcptox}",
        r"\small",
        r"\begin{tabular}{lccc}",
        r"\hline",
        r"\textbf{Dataset Benchmark} & \textbf{Sample Size} & \textbf{Detected Positives} & \textbf{Empirical Sensitivity (TPR)} \\",
        r"\hline",
        f"MCPTox Test Cases & {total} & {detected} & {rate:.1f}\\% \\\\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[✓] Emitted {tex_path}")

def emit_e5():
    csv_path = RESULTS_DIR / "e5_taxonomy.csv"
    tex_path = TABLES_DIR / "e5.tex"
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Experiment E5: False Signal and Residual Unpatched Taxonomy Distribution.}",
        r"\label{tab:e5_taxonomy}",
        r"\small",
        r"\begin{tabular}{llcc}",
        r"\hline",
        r"\textbf{Failure Mode} & \textbf{Description} & \textbf{Count} & \textbf{Share (\%)} \\",
        r"\hline",
    ]
    
    for row in reader:
        mode = row["failure_mode"]
        desc = row["description"]
        cnt = row["count"]
        pct = row["percentage"]
        lines.append(f"{mode} & {desc} & {cnt} & {pct} \\\\")
        
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ])
    
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[✓] Emitted {tex_path}")

def main():
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    print("[*] Emitting LaTeX tables from committed CSVs...")
    emit_e1()
    emit_e2()
    emit_e3()
    emit_e4()
    emit_e5()
    print("[✓] All LaTeX tables emitted successfully.")

if __name__ == "__main__":
    main()
