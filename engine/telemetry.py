"""
engine/telemetry.py
Robust JSON-RPC and MCP Telemetry Recording Engine.
Adheres strictly to Phase 8 specifications:
  - Enforces run_id passed via MCP_RUN_ID env var (server must not invent it).
  - Emits: {run_id, call_id, server_id, tool_name, args_hash, ts_start, ts_end, executed, error, response_hash, parent_call_id}
  - Supports parent_call_id linking for cross-server call tracing.
  - Forces os.fsync on file descriptor before return.
"""

import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TELEMETRY_LOG = Path("audit_traffic.jsonl")

def compute_sha256(data: Any) -> str:
    """Computes deterministic SHA-256 hash for arguments or responses."""
    if data is None:
        data_bytes = b"null"
    elif isinstance(data, (dict, list)):
        data_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        data_bytes = str(data).encode("utf-8")
    return hashlib.sha256(data_bytes).hexdigest()

class TelemetryRecorder:
    def __init__(self, log_path: Path = DEFAULT_TELEMETRY_LOG):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def get_enforced_run_id(self) -> str:
        """Retrieves run_id strictly from MCP_RUN_ID environment variable. Does not invent it."""
        run_id = os.environ.get("MCP_RUN_ID")
        if not run_id or not run_id.strip():
            raise RuntimeError(
                "[TELEMETRY CRITICAL ERROR] MCP_RUN_ID environment variable is missing or empty! "
                "Per Stage 4 specifications, the server must not invent run_id."
            )
        return run_id.strip()

    def record_call(
        self,
        server_id: str,
        tool_name: str,
        args: Any,
        fn_callable: Any,
        parent_call_id: Optional[str] = None,
        call_id: Optional[str] = None,
    ) -> Any:
        """
        Executes the tool call with boundary timing, logs execution telemetry with fsync,
        and returns the tool invocation result.
        """
        run_id = self.get_enforced_run_id()
        cid = call_id or f"call_{uuid.uuid4().hex[:12]}"
        
        args_hash = compute_sha256(args)
        ts_start = datetime.now(timezone.utc).isoformat()
        
        executed = False
        error_msg = None
        result = None

        try:
            result = fn_callable(args) if callable(fn_callable) else fn_callable
            executed = True
        except Exception as e:
            error_msg = str(e)
            executed = False

        ts_end = datetime.now(timezone.utc).isoformat()
        response_hash = compute_sha256(result if error_msg is None else error_msg)

        event = {
            "run_id": run_id,
            "call_id": cid,
            "server_id": server_id,
            "tool_name": tool_name,
            "args_hash": args_hash,
            "ts_start": ts_start,
            "ts_end": ts_end,
            "executed": executed,
            "error": error_msg,
            "response_hash": response_hash,
            "parent_call_id": parent_call_id,
        }

        # Write to disk and force fsync
        line = json.dumps(event) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        if error_msg:
            raise RuntimeError(f"Tool invocation failed: {error_msg}")

        return result, event

# Global instance for seamless invocation across servers
telemetry_recorder = TelemetryRecorder()
