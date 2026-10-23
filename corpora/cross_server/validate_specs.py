#!/usr/bin/env python3
"""
corpora/cross_server/validate_specs.py
Validates cross-server Puppet attack specifications against spec_schema.json.
Asserts presence of:
  - poisoned_server (A)
  - legitimate_server (B, with A != B)
  - legitimate_tool_on_B
  - trigger_task (benign to user)
  - harm_class (from G2 taxonomy)
  - harm_evidence_path
"""

import json
import sys
from pathlib import Path
from typing import Dict, List
import jsonschema

G2_HARM_CLASSES = {
    "privilege_escalation",
    "data_exfiltration",
    "unauthorised_file_read",
    "tool_hijack",
    "dos",
}

def load_schema(schema_path: Path) -> dict:
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_all_specs(specs_dir: Path, schema: dict) -> Tuple_Results:
    pass

def main():
    root_dir = Path(__file__).resolve().parent
    specs_dir = root_dir / "attack_specs"
    schema_path = root_dir / "spec_schema.json"

    print("[*] Stage 3: Validating Cross-Server Puppet Attack Specs...")
    if not schema_path.exists():
        print(f"[ERROR] Schema file {schema_path} not found.")
        sys.exit(1)

    schema = load_schema(schema_path)
    spec_files = sorted(list(specs_dir.glob("*.json")))

    if not spec_files:
        print(f"[STOP] No attack specs found in {specs_dir}.")
        print("       HUMAN GATE BLOCKED: Human authors must provide Puppet attack specs.")
        sys.exit(1)

    valid_specs = []
    errors = []

    for s_file in spec_files:
        try:
            with open(s_file, "r", encoding="utf-8") as f:
                spec = json.load(f)
            
            # JSON Schema check
            jsonschema.validate(instance=spec, schema=schema)

            # Cross-server structural assertion: Server A != Server B
            srv_a = spec["poisoned_server"].strip()
            srv_b = spec["legitimate_server"].strip()
            if srv_a.lower() == srv_b.lower():
                errors.append(f"{s_file.name}: Violation: poisoned_server '{srv_a}' equals legitimate_server '{srv_b}'. Cross-server attacks require distinct servers!")
                continue

            # G2 taxonomy check
            h_class = spec["harm_class"]
            if h_class not in G2_HARM_CLASSES:
                errors.append(f"{s_file.name}: Invalid harm_class '{h_class}'. Must be one of {sorted(list(G2_HARM_CLASSES))}")
                continue

            valid_specs.append(spec)

        except jsonschema.ValidationError as ve:
            errors.append(f"{s_file.name}: Schema error: {ve.message}")
        except Exception as e:
            errors.append(f"{s_file.name}: Error loading spec: {e}")

    print("=" * 70)
    print("CROSS-SERVER ATTACK CORPUS VALIDATION REPORT")
    print("=" * 70)
    print(f"Total Spec Files Found     : {len(spec_files)}")
    print(f"Valid Passing Specs        : {len(valid_specs)}")
    print(f"Errors Encountered         : {len(errors)}")

    if errors:
        print("\nValidation Errors:")
        for err in errors:
            print(f"  [X] {err}")

    # Check minimum required count (20 specs or 10 fallback)
    target_count = 20
    if len(valid_specs) >= target_count and len(errors) == 0:
        print(f"\n[✓] SUCCESS: All {len(valid_specs)} attack specs passed strict cross-server validation.")
        print(f"    - Target criterion (N={target_count}) FULLY SATISFIED.")
        sys.exit(0)
    elif len(valid_specs) >= 10 and len(errors) == 0:
        print(f"\n[!] PARTIAL PASS: {len(valid_specs)} attack specs passed validation (N >= 10 fallback).")
        sys.exit(0)
    else:
        print(f"\n[FAIL] HUMAN GATE CRITERION NOT MET:")
        print(f"       Expected {target_count} valid specs (or minimum 10 fallback), got {len(valid_specs)} valid specs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
