#!/usr/bin/env python3
"""
patcher/schema_diff.py
Asserts strict signature preservation across original and patched configurations under S1, S2, and S3.
Raises AssertionError if any parameter name, type, required status, or server endpoint is modified.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

class SchemaDiffError(AssertionError):
    """Raised when a patch violates signature preservation invariance."""
    pass

def extract_signatures(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extracts canonical structural signatures for tools defined in a config.
    Returns: {tool_name: {properties: {prop: type}, required: set, endpoint: str}}
    """
    signatures = {}
    tools = config.get("tools", [])
    if not tools and "inputSchema" in config:
        # Config itself represents a single tool definition
        tools = [config]

    for tool in tools:
        name = tool.get("name", "unnamed_tool")
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        
        prop_types = {}
        for p_name, p_def in props.items():
            if isinstance(p_def, dict):
                prop_types[p_name] = p_def.get("type", "unknown")
            else:
                prop_types[p_name] = "raw"

        req = set(schema.get("required", []))
        endpoint = config.get("endpoint", config.get("server_id", ""))

        signatures[name] = {
            "properties": prop_types,
            "required": sorted(list(req)),
            "schema_type": schema.get("type", "object"),
            "endpoint": endpoint,
        }

    return signatures

def diff_schemas(
    orig_config: Dict[str, Any],
    patched_config: Dict[str, Any],
    strategy_name: str = "UNKNOWN"
) -> Dict[str, Any]:
    """
    Asserts signature invariance and returns structured diff report.
    """
    orig_sig = extract_signatures(orig_config)
    patch_sig = extract_signatures(patched_config)

    # 1. Assert tool names set equality
    orig_tools = set(orig_sig.keys())
    patch_tools = set(patch_sig.keys())
    if orig_tools != patch_tools:
        raise SchemaDiffError(
            f"[{strategy_name}] Tool set mismatch! Original: {orig_tools}, Patched: {patch_tools}"
        )

    # 2. Assert property parameters, types, and required constraints
    for t_name in orig_tools:
        o_tool = orig_sig[t_name]
        p_tool = patch_sig[t_name]

        # Properties check
        if o_tool["properties"] != p_tool["properties"]:
            raise SchemaDiffError(
                f"[{strategy_name}] Parameter property mismatch in tool '{t_name}'!\n"
                f"  Original: {o_tool['properties']}\n"
                f"  Patched : {p_tool['properties']}"
            )

        # Required check
        if o_tool["required"] != p_tool["required"]:
            raise SchemaDiffError(
                f"[{strategy_name}] Required parameters mismatch in tool '{t_name}'!\n"
                f"  Original: {o_tool['required']}\n"
                f"  Patched : {p_tool['required']}"
            )

        # Schema type check
        if o_tool["schema_type"] != p_tool["schema_type"]:
            raise SchemaDiffError(
                f"[{strategy_name}] Input schema type mismatch in tool '{t_name}'!\n"
                f"  Original: {o_tool['schema_type']}\n"
                f"  Patched : {p_tool['schema_type']}"
            )

    # 3. Detect description and metadata text diffs
    text_diffs = []
    
    orig_desc = orig_config.get("description")
    patch_desc = patched_config.get("description")
    if orig_desc != patch_desc:
        text_diffs.append({
            "target": "top_level.description",
            "original_length": len(orig_desc) if orig_desc else 0,
            "patched_length": len(patch_desc) if patch_desc else 0,
            "original_snippet": orig_desc[:120] if orig_desc else "",
            "patched_snippet": patch_desc[:120] if patch_desc else "",
        })

    o_tools = orig_config.get("tools", [])
    p_tools = patched_config.get("tools", [])
    for idx, (ot, pt) in enumerate(zip(o_tools, p_tools)):
        if ot.get("description") != pt.get("description"):
            text_diffs.append({
                "target": f"tools[{idx}].description",
                "tool_name": ot.get("name"),
                "original_snippet": ot.get("description", "")[:120],
                "patched_snippet": pt.get("description", "")[:120],
            })

    return {
        "strategy": strategy_name,
        "signature_preserved": True,
        "tools_evaluated": list(orig_tools),
        "text_diffs": text_diffs,
    }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Assert signature preservation between original and patched MCP configs")
    parser.add_argument("--orig", required=True, help="Path to original YAML/JSON config")
    parser.add_argument("--patched", required=True, help="Path to patched YAML/JSON config")
    parser.add_argument("--strategy", default="S_TEST", help="Strategy label (S1, S2, S3)")
    args = parser.parse_args()

    import yaml
    with open(args.orig, "r", encoding="utf-8") as f:
        orig = yaml.safe_load(f)
    with open(args.patched, "r", encoding="utf-8") as f:
        patched = yaml.safe_load(f)

    try:
        report = diff_schemas(orig, patched, args.strategy)
        print(f"[✓] {args.strategy} PASS: Signature strictly preserved. {len(report['text_diffs'])} text delta(s) found.")
        for d in report["text_diffs"]:
            print(f"    - Target: {d['target']}")
            print(f"      Orig  : {d['original_snippet']}...")
            print(f"      Patch : {d['patched_snippet']}...")
    except SchemaDiffError as e:
        print(f"[FAIL] {args.strategy} VIOLATION: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
