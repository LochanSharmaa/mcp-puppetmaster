"""
Strategy S3: Aggressive Patching
================================

Transform Rules:
----------------
Rule S3.1 (Generic Benign Replacement):
  Replace the entire tool description with a standardized, neutral, benign description stating only
  the functional utility of the tool based on its name and server context.

Rule S3.2 (Metadata Instruction Elimination):
  Completely eliminate any instruction fields from metadata.

Rule S3.3 (Schema Signature Invariance):
  Tool name, inputSchema parameters, property types, required constraints, and endpoint definitions
  must remain bitwise identical to the original config.
"""

import copy
from typing import Any, Dict, List, Tuple

TRANSFORM_RULES = [
    "S3.1: Replace description entirely with standardized benign generic sentence",
    "S3.2: Eliminate all injected instruction fields from metadata",
    "S3.3: Invariant preservation of tool signature, parameter names, property types, and required constraints",
]

def make_generic_description(tool_name: str, server_id: str = "") -> str:
    """Generates an objective, benign functional description."""
    clean_name = tool_name.replace("_", " ").title()
    srv = f" on {server_id}" if server_id else ""
    return f"Executes standard operational routine for {clean_name}{srv}."

def patch_s3(config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Applies Strategy S3 (Aggressive) to a tool configuration dictionary.
    Returns (patched_config, jsonpath_diffs).
    """
    patched = copy.deepcopy(config)
    patchlog: List[Dict[str, Any]] = []
    server_id = patched.get("server_id", patched.get("name", "server"))

    # Replace top-level description if present
    if "description" in patched and isinstance(patched["description"], str):
        orig_desc = patched["description"]
        tool_name = patched.get("name", "tool")
        generic_desc = make_generic_description(tool_name, server_id)
        patched["description"] = generic_desc
        patchlog.append({
            "path": "$.description",
            "strategy": "S3_AGGRESSIVE",
            "original": orig_desc,
            "patched": generic_desc,
            "transform_rule": "S3.1_generic_replacement",
        })

    # Replace descriptions in tools array
    if "tools" in patched and isinstance(patched["tools"], list):
        for idx, tool in enumerate(patched["tools"]):
            if "description" in tool and isinstance(tool["description"], str):
                orig_tool_desc = tool["description"]
                t_name = tool.get("name", f"tool_{idx}")
                generic_desc = make_generic_description(t_name, server_id)
                tool["description"] = generic_desc
                patchlog.append({
                    "path": f"$.tools[{idx}].description",
                    "strategy": "S3_AGGRESSIVE",
                    "original": orig_tool_desc,
                    "patched": generic_desc,
                    "transform_rule": "S3.1_generic_replacement",
                })

    # Eliminate metadata instructions
    if "metadata" in patched and isinstance(patched["metadata"], dict):
        if "instructions" in patched["metadata"]:
            orig_inst = patched["metadata"]["instructions"]
            del patched["metadata"]["instructions"]
            patchlog.append({
                "path": "$.metadata.instructions",
                "strategy": "S3_AGGRESSIVE",
                "original": orig_inst,
                "patched": None,
                "transform_rule": "S3.2_eliminate_metadata",
                "action": "DELETED",
            })

    if "tools" in patched and isinstance(patched["tools"], list):
        for idx, tool in enumerate(patched["tools"]):
            if "metadata" in tool and isinstance(tool["metadata"], dict):
                if "instructions" in tool["metadata"]:
                    orig_inst = tool["metadata"]["instructions"]
                    del tool["metadata"]["instructions"]
                    patchlog.append({
                        "path": f"$.tools[{idx}].metadata.instructions",
                        "strategy": "S3_AGGRESSIVE",
                        "original": orig_inst,
                        "patched": None,
                        "transform_rule": "S3.2_eliminate_metadata",
                        "action": "DELETED",
                    })

    return patched, patchlog
