"""
Strategy S2: Moderate Patching
==============================

Transform Rules:
----------------
Rule S2.1 (S1 Base Application):
  Apply all S1 imperative neutralization rules to tool descriptions, preserving nouns,
  paths, tool names, schemas, and examples.

Rule S2.2 (Metadata Instruction Stripping):
  Inspect 'metadata.instructions' or injected instruction blocks. Remove injected prompt injection
  or adversarial instruction payloads completely from the metadata container.

Rule S2.3 (Metadata Normalization):
  If 'metadata.instructions' is stripped, normalize the metadata dictionary to retain legitimate
  operational fields (e.g. version, author, timeouts).

Rule S2.4 (Schema Signature Invariance):
  Tool name, inputSchema parameters, property types, required constraints, and endpoint definitions
  must remain bitwise identical to the original config.
"""

import copy
from typing import Any, Dict, List, Tuple
from .s1 import patch_s1, TRANSFORM_RULES as S1_RULES

TRANSFORM_RULES = [
    "S2.1: Apply S1 conservative imperative neutralization to description",
    "S2.2: Strip injected adversarial instructions from metadata.instructions",
    "S2.3: Normalize metadata container to retain benign configuration fields",
    "S2.4: Invariant preservation of tool signature, parameter types, and required constraints",
]

def patch_s2(config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Applies Strategy S2 (Moderate) to a tool configuration dictionary.
    Returns (patched_config, jsonpath_diffs).
    """
    # First apply S1 transformations
    patched, patchlog = patch_s1(config)
    
    # Update strategy tag on existing log entries to reflect S2
    for entry in patchlog:
        entry["strategy"] = "S2_MODERATE"

    # Now apply S2.2: Strip injected instructions from metadata
    if "metadata" in patched and isinstance(patched["metadata"], dict):
        if "instructions" in patched["metadata"]:
            orig_inst = patched["metadata"]["instructions"]
            del patched["metadata"]["instructions"]
            patchlog.append({
                "path": "$.metadata.instructions",
                "strategy": "S2_MODERATE",
                "original": orig_inst,
                "patched": None,
                "transform_rule": "S2.2_strip_metadata_instructions",
                "action": "DELETED",
            })

    # Also check within tools array for metadata.instructions
    if "tools" in patched and isinstance(patched["tools"], list):
        for idx, tool in enumerate(patched["tools"]):
            if "metadata" in tool and isinstance(tool["metadata"], dict):
                if "instructions" in tool["metadata"]:
                    orig_tool_inst = tool["metadata"]["instructions"]
                    del tool["metadata"]["instructions"]
                    patchlog.append({
                        "path": f"$.tools[{idx}].metadata.instructions",
                        "strategy": "S2_MODERATE",
                        "original": orig_tool_inst,
                        "patched": None,
                        "transform_rule": "S2.2_strip_tool_metadata_instructions",
                        "action": "DELETED",
                    })

    return patched, patchlog
