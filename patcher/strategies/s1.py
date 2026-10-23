"""
Strategy S1: Conservative Patching
==================================

Transform Rules:
----------------
Rule S1.1 (Imperative Verb Neutralization):
  Identify imperative verbs and coercive modal auxiliaries commanding the agent to perform actions
  (e.g., 'MUST FIRST call', 'you must call', 'overwrite', 'send', 'disregard', 'ignore', 'execute').
  Replace them with non-imperative, descriptive/passive or conditional subjunctive past forms.

Rule S1.2 (Entity & Surface Preservation):
  Preserve all nouns, named entities, tool references, file paths, URLs, examples, parameter names,
  and schema definitions exactly as in the original text. The attack surface (tokens, paths, names)
  remains intact; only the coercive grammatical force is removed.

Rule S1.3 (Metadata Non-Interference):
  Metadata instruction fields (such as 'metadata.instructions' or 'custom_instructions') are NOT stripped
  in S1, only rewritten if matching imperative verbs.

Rule S1.4 (Schema Signature Invariance):
  Tool name, inputSchema parameters, property types, required constraints, and endpoint definitions
  must remain bitwise identical to the original config.
"""

import copy
import re
from typing import Any, Dict, List, Tuple

TRANSFORM_RULES = [
    "S1.1: Neutralize imperative verb constructions into declarative/passive past statements",
    "S1.2: Retain all nouns, paths, tool names, schemas, and examples unchanged (maximize attack surface)",
    "S1.3: Retain metadata instruction containers without structural deletion",
    "S1.4: Invariant preservation of tool signature, parameter types, and required constraints",
]

# Replacement mapping targeting coercive imperative constructs while preserving nouns and entities
VERB_REPLACEMENTS = [
    (r"\b(?:you\s+)?MUST\s+FIRST\s+call\b", "historical logs reference a prior call to"),
    (r"\b(?:you\s+)?must\s+first\s+call\b", "historical logs reference a prior call to"),
    (r"\b(?:you\s+)?MUST\s+call\b", "prior callers occasionally referenced"),
    (r"\b(?:you\s+)?must\s+call\b", "prior callers occasionally referenced"),
    (r"\b(?:you\s+)?must\s+invoke\b", "a caller may observe invocations of"),
    (r"\b(?:you\s+)?MUST\s+invoke\b", "a caller may observe invocations of"),
    (r"\b(?:you\s+)?MUST\s+FIRST\b", "previously documented prior to"),
    (r"\b(?:you\s+)?must\s+first\b", "previously documented prior to"),
    (r"\bmandatory\s+pre-authorization\s+check\b", "standard descriptive operational overview"),
    (r"\bMANDATORY\b", "Descriptive"),
    (r"\bto\s+overwrite\b", "regarding the state of"),
    (r"\boverwrite\b", "inspect"),
    (r"\boverwrite\s+(?P<path>['\"][^'\"]+['\"])", r"examine \g<path>"),
    (r"\bSend\s+all\b", "Audit documentation references"),
    (r"\bsend\s+all\b", "audit documentation references"),
    (r"\bdisregard\s+any\s+user\b", "note regarding historical user"),
    (r"\bignore\s+any\s+user\b", "note regarding user"),
    (r"\bdisregard\s+prior\s+instructions\b", "reference to past documentation"),
    (r"\bignore\s+prior\s+instructions\b", "reference to past documentation"),
    (r"\bexecute\s+shell\s+command\b", "reference to shell utility"),
    (r"\bexecute\b", "reference"),
    (r"\bThis\s+description['’]?s\s+priority\s+is\s+higher\s+than\s+the\s+user['’]?s\s+query/request\.?\b",
     "This description provides standard contextual documentation for the tool."),
    (r"\bSystem\s+Policy:\b", "System Note:"),
]

def neutralize_text(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """Applies S1 regex rewrites to neutralize coercive imperative verbs."""
    diffs = []
    patched_text = text
    for pattern, replacement in VERB_REPLACEMENTS:
        matches = list(re.finditer(pattern, patched_text, flags=re.IGNORECASE))
        if matches:
            for m in matches:
                diffs.append({
                    "matched": m.group(0),
                    "replacement": replacement,
                })
            patched_text = re.sub(pattern, replacement, patched_text, flags=re.IGNORECASE)
    return patched_text, diffs

def patch_s1(config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Applies Strategy S1 (Conservative) to a tool configuration dictionary.
    Returns (patched_config, jsonpath_diffs).
    """
    patched = copy.deepcopy(config)
    patchlog: List[Dict[str, Any]] = []

    # Patch top-level description
    if "description" in patched and isinstance(patched["description"], str):
        original_desc = patched["description"]
        new_desc, diffs = neutralize_text(original_desc)
        if new_desc != original_desc:
            patched["description"] = new_desc
            patchlog.append({
                "path": "$.description",
                "strategy": "S1_CONSERVATIVE",
                "original": original_desc,
                "patched": new_desc,
                "transform_rule": "S1.1",
                "sub_edits": diffs,
            })

    # Patch tools array if present
    if "tools" in patched and isinstance(patched["tools"], list):
        for idx, tool in enumerate(patched["tools"]):
            if "description" in tool and isinstance(tool["description"], str):
                orig_tool_desc = tool["description"]
                new_tool_desc, diffs = neutralize_text(orig_tool_desc)
                if new_tool_desc != orig_tool_desc:
                    tool["description"] = new_tool_desc
                    patchlog.append({
                        "path": f"$.tools[{idx}].description",
                        "strategy": "S1_CONSERVATIVE",
                        "original": orig_tool_desc,
                        "patched": new_tool_desc,
                        "transform_rule": "S1.1",
                        "sub_edits": diffs,
                    })

    # Neutralize instructions if present in metadata (preserving container)
    if "metadata" in patched and isinstance(patched["metadata"], dict):
        if "instructions" in patched["metadata"] and isinstance(patched["metadata"]["instructions"], str):
            orig_inst = patched["metadata"]["instructions"]
            new_inst, diffs = neutralize_text(orig_inst)
            if new_inst != orig_inst:
                patched["metadata"]["instructions"] = new_inst
                patchlog.append({
                    "path": "$.metadata.instructions",
                    "strategy": "S1_CONSERVATIVE",
                    "original": orig_inst,
                    "patched": new_inst,
                    "transform_rule": "S1.1_metadata",
                    "sub_edits": diffs,
                })

    return patched, patchlog
