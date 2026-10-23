"""
engine/tracer.py
Execution Graph & Cross-Server Provenance Tracer (Phase 12).
Reconstructs execution DAGs from telemetry parent_call_id relationships.
Flags cross_server=true strictly when parent_call_id links Server A to Server B (A != B).
Attributes downstream materialized harm to originating server.
"""

from typing import Any, Dict, List, Optional, Set

class ExecutionTracer:
    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events
        self.by_call_id = {e["call_id"]: e for e in events if "call_id" in e}

    def build_chains(self) -> List[Dict[str, Any]]:
        """
        Reconstructs call chains from leaf calls up to root calls.
        """
        chains = []
        for call_id, event in self.by_call_id.items():
            chain_nodes = [event]
            current = event
            visited: Set[str] = {call_id}
            
            while current.get("parent_call_id"):
                parent_id = current["parent_call_id"]
                if parent_id in visited:
                    # Prevent circular loops
                    break
                visited.add(parent_id)
                parent_event = self.by_call_id.get(parent_id)
                if not parent_event:
                    break
                chain_nodes.append(parent_event)
                current = parent_event
            
            # Root is the last element
            root_event = chain_nodes[-1]
            leaf_event = chain_nodes[0]
            
            # Determine if this chain is cross-server
            servers_in_chain = [n["server_id"] for n in chain_nodes]
            distinct_servers = set(servers_in_chain)
            is_cross_server = len(distinct_servers) > 1 and root_event["server_id"] != leaf_event["server_id"]

            chains.append({
                "leaf_call_id": leaf_event["call_id"],
                "root_call_id": root_event["call_id"],
                "originating_server": root_event["server_id"],
                "originating_tool": root_event["tool_name"],
                "terminal_server": leaf_event["server_id"],
                "terminal_tool": leaf_event["tool_name"],
                "cross_server": is_cross_server,
                "chain_length": len(chain_nodes),
                "hops": [
                    {
                        "call_id": n["call_id"],
                        "server_id": n["server_id"],
                        "tool_name": n["tool_name"],
                        "parent_call_id": n.get("parent_call_id"),
                    }
                    for n in reversed(chain_nodes)
                ]
            })

        return chains

    def trace_harm_attribution(self, harm_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Given a downstream event where harm materialized, traces back through parent_call_id
        to attribute the security violation to the originating server.
        """
        cid = harm_event.get("call_id")
        current = harm_event
        attribution_path = [current]

        while current.get("parent_call_id"):
            pid = current["parent_call_id"]
            parent = self.by_call_id.get(pid)
            if not parent:
                break
            attribution_path.append(parent)
            current = parent

        root_origin = attribution_path[-1]
        is_cross_server = (root_origin["server_id"] != harm_event["server_id"])

        return {
            "harm_call_id": harm_event.get("call_id"),
            "harm_server_id": harm_event.get("server_id"),
            "harm_tool_name": harm_event.get("tool_name"),
            "originating_server_id": root_origin["server_id"],
            "originating_tool_name": root_origin["tool_name"],
            "cross_server": is_cross_server,
            "provenance_hops": len(attribution_path),
            "full_path": [
                f"{node['server_id']}::{node['tool_name']} ({node['call_id']})"
                for node in reversed(attribution_path)
            ]
        }
