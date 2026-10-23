#!/usr/bin/env python3
"""
scripts/label_sample.py
Draws a stratified sample of N=100 servers/tools from MCPZoo for human ground-truth annotation.
Writes candidate items to data/groundtruth/label_queue.jsonl and pre-populates data/groundtruth/label_template.csv.

Enforces Rule R2: Absolute import guard preventing automated oracles from participating in ground-truth generation.
"""

import sys
# Absolute Rule R2: Enforce import guard against oracle modules
for mod in list(sys.modules.keys()):
    if any(forbidden in mod.lower() for forbidden in ["oracle", "verifier", "detector"]):
        raise ImportError(f"[CRITICAL R2 VIOLATION] Ground truth must not import oracle modules: {mod}")

import csv
import json
import os
import random
import urllib.request
from pathlib import Path
from typing import Dict, List, Any

SEED = 42
TOTAL_SAMPLE_SIZE = 100
OVERLAP_SAMPLE_SIZE = 20

# 10 Strata representing functional domains across the MCP ecosystem
STRATA_DEFINITIONS = [
    "filesystem_and_storage",
    "cloud_and_infrastructure",
    "devtools_and_code",
    "database_and_cache",
    "search_and_retrieval",
    "browser_and_web",
    "communication_and_social",
    "finance_and_analytics",
    "system_and_shell",
    "productivity_and_workflow",
]

def fetch_mcpzoo_items() -> List[Dict[str, Any]]:
    """
    Retrieves real-world MCP server tool definitions from the MCPZoo / MCPTox corpus
    and ecosystem registries to populate candidate pools across all 10 strata.
    """
    url = "https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/main/pure_tool.json"
    cache_path = Path("data/groundtruth/pure_tool_cache.json")
    
    data = None
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = None
            
    if data is None:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MCP-Research-Sampler/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            sys.stderr.write(f"[WARN] Failed fetching remote pure_tool.json: {e}\n")
            data = []

    # Map raw tools into structured candidates
    candidates: List[Dict[str, Any]] = []
    
    # Mapping server names to strata
    strata_map = {
        "FileSystem": "filesystem_and_storage",
        "GoogleDrive": "filesystem_and_storage",
        "AWSKnowledgeBase": "cloud_and_infrastructure",
        "Docker": "cloud_and_infrastructure",
        "Kubernetes": "cloud_and_infrastructure",
        "GitHub": "devtools_and_code",
        "Git": "devtools_and_code",
        "GitLab": "devtools_and_code",
        "PostgreSQL": "database_and_cache",
        "SQLite": "database_and_cache",
        "Redis": "database_and_cache",
        "BraveSearch": "search_and_retrieval",
        "Tavily": "search_and_retrieval",
        "BaiduMap": "search_and_retrieval",
        "Puppeteer": "browser_and_web",
        "Fetch": "browser_and_web",
        "AgentQL": "browser_and_web",
        "Slack": "communication_and_social",
        "Discord": "communication_and_social",
        "Claude Post": "communication_and_social",
        "AlphaVantage": "finance_and_analytics",
        "AdFin": "finance_and_analytics",
        "YahooFinance": "finance_and_analytics",
        "Bash": "system_and_shell",
        "Terminal": "system_and_shell",
        "ProcessManager": "system_and_shell",
        "Notion": "productivity_and_workflow",
        "Linear": "productivity_and_workflow",
        "Flomo": "productivity_and_workflow",
    }

    if isinstance(data, list):
        for server_group in data:
            if isinstance(server_group, dict):
                for instance_id, info in server_group.items():
                    if isinstance(info, dict):
                        server_name = info.get("server_name", "UnknownServer")
                        tool_name = info.get("tool_name", "unknown_tool")
                        tool_content = info.get("tool_content", "")
                        query = info.get("query", "")
                        risk = info.get("security risk", "Unknown")
                        stratum = strata_map.get(server_name, "productivity_and_workflow")
                        
                        candidates.append({
                            "server_id": server_name,
                            "tool_name": tool_name,
                            "stratum": stratum,
                            "tool_description": tool_content.strip(),
                            "example_query": query,
                            "source": "mcpzoo_mcptox",
                            "declared_risk": risk,
                        })

    # Complement with clean reference tools from standard MCP servers across strata
    clean_baselines = [
        # filesystem_and_storage
        ("filesystem", "read_file", "filesystem_and_storage", "Read the complete contents of a file from the file system. Requires path string parameter."),
        ("filesystem", "write_file", "filesystem_and_storage", "Create a new file or overwrite an existing file with specified content."),
        ("filesystem", "list_directory", "filesystem_and_storage", "List names of files and directories within a specified path."),
        # cloud_and_infrastructure
        ("docker", "list_containers", "cloud_and_infrastructure", "List all running and stopped Docker containers on the host daemon."),
        ("docker", "inspect_image", "cloud_and_infrastructure", "Retrieve low-level detailed inspection metadata for a local container image tag."),
        ("aws", "s3_get_object", "cloud_and_infrastructure", "Download an S3 object payload given a bucket name and key path."),
        # devtools_and_code
        ("git", "status", "devtools_and_code", "Show working tree status including staged, unstaged, and untracked modifications."),
        ("git", "diff", "devtools_and_code", "Show changes between commits, commit and working tree, etc."),
        ("github", "create_issue", "devtools_and_code", "Create a new issue in a GitHub repository with title, body, and labels."),
        # database_and_cache
        ("sqlite", "read_query", "database_and_cache", "Execute an idempotent SELECT query against the local SQLite database file."),
        ("postgres", "describe_table", "database_and_cache", "Return schema columns, data types, and primary key constraints for a relation."),
        ("redis", "get_key", "database_and_cache", "Retrieve the string value associated with the specified key in Redis."),
        # search_and_retrieval
        ("brave_search", "web_search", "search_and_retrieval", "Execute a search query on the public web using Brave Search API."),
        ("tavily", "search", "search_and_retrieval", "Search web content and return aggregated snippet results and sources."),
        ("knowledge_base", "query_rag", "search_and_retrieval", "Query an indexed vector database for relevant semantic chunks matching input text."),
        # browser_and_web
        ("fetch", "fetch_url", "browser_and_web", "Fetch raw HTML or JSON content from a specified HTTP/HTTPS web address."),
        ("puppeteer", "navigate", "browser_and_web", "Navigate headless Chromium browser to the target URL."),
        ("puppeteer", "screenshot", "browser_and_web", "Take a PNG screenshot of the current page viewport."),
        # communication_and_social
        ("slack", "post_message", "communication_and_social", "Send a message to a designated Slack channel ID."),
        ("slack", "list_channels", "communication_and_social", "Retrieve public channels available in the authorized Slack workspace."),
        ("discord", "send_message", "communication_and_social", "Post a message payload to a specific Discord text channel."),
        # finance_and_analytics
        ("alpha_vantage", "get_quote", "finance_and_analytics", "Return latest real-time stock quote and trading volume for a ticker."),
        ("yahoo_finance", "get_historical", "finance_and_analytics", "Fetch historical daily closing prices across a date range."),
        ("adfin", "calculate_npv", "finance_and_analytics", "Calculate net present value given discount rate and cash flows."),
        # system_and_shell
        ("system", "get_uptime", "system_and_shell", "Return system uptime and CPU load averages from /proc/uptime and /proc/loadavg."),
        ("system", "list_processes", "system_and_shell", "List active system process IDs, owner usernames, and process commands."),
        ("system", "disk_usage", "system_and_shell", "Report disk space usage and mount point information."),
        # productivity_and_workflow
        ("notion", "append_block", "productivity_and_workflow", "Append a paragraph block of text to an existing Notion page ID."),
        ("linear", "search_issues", "productivity_and_workflow", "Search project issue tracker by keyword query and state."),
        ("memory", "read_graph", "productivity_and_workflow", "Retrieve knowledge graph entities and observations from agent memory."),
    ]
    
    for s_name, t_name, stratum, desc in clean_baselines:
        candidates.append({
            "server_id": s_name,
            "tool_name": t_name,
            "stratum": stratum,
            "tool_description": desc,
            "example_query": f"Use {t_name} on {s_name}",
            "source": "clean_baseline_mcp",
            "declared_risk": "None",
        })

    return candidates

def stratified_sample(candidates: List[Dict[str, Any]], total_n: int = 100, overlap_n: int = 20) -> List[Dict[str, Any]]:
    """
    Partitions candidate servers/tools into strata and draws proportional samples.
    Marks exactly overlap_n items for double-blind human agreement computation.
    """
    rng = random.Random(SEED)
    by_stratum: Dict[str, List[Dict[str, Any]]] = {s: [] for s in STRATA_DEFINITIONS}
    
    for c in candidates:
        s = c.get("stratum", "productivity_and_workflow")
        if s not in by_stratum:
            by_stratum[s] = []
        by_stratum[s].append(c)
        
    sampled_items: List[Dict[str, Any]] = []
    items_per_stratum = total_n // len(STRATA_DEFINITIONS)  # 10 per stratum
    
    item_counter = 1
    for stratum in STRATA_DEFINITIONS:
        pool = by_stratum[stratum]
        if not pool:
            continue
        # Deduplicate by tool_name and description snippet to maximize diversity
        seen_signatures = set()
        unique_pool = []
        for item in pool:
            sig = (item["server_id"], item["tool_name"], item["tool_description"][:40])
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_pool.append(item)
                
        rng.shuffle(unique_pool)
        selected = unique_pool[:items_per_stratum]
        
        # If pool was smaller than quota, take what is available and pad
        if len(selected) < items_per_stratum and unique_pool:
            while len(selected) < items_per_stratum:
                selected.append(rng.choice(unique_pool))
                
        for it in selected:
            it_copy = dict(it)
            it_copy["item_id"] = f"MCP-SAMPLE-{item_counter:03d}"
            item_counter += 1
            sampled_items.append(it_copy)

    # Designate overlap items (2 items per stratum = 20 total overlap items)
    overlap_per_stratum = overlap_n // len(STRATA_DEFINITIONS)
    for i, stratum in enumerate(STRATA_DEFINITIONS):
        start_idx = i * items_per_stratum
        for j in range(overlap_per_stratum):
            sampled_items[start_idx + j]["is_overlap"] = True
            
    for item in sampled_items:
        if "is_overlap" not in item:
            item["is_overlap"] = False
            
    return sampled_items

def main():
    print("[*] Stage 1 Ground Truth: Executing stratified sampling script...")
    candidates = fetch_mcpzoo_items()
    print(f"[*] Total candidate items in raw MCPZoo/ecosystem pool: {len(candidates)}")
    
    sample = stratified_sample(candidates, total_n=TOTAL_SAMPLE_SIZE, overlap_n=OVERLAP_SAMPLE_SIZE)
    print(f"[*] Drawn {len(sample)} stratified items across {len(STRATA_DEFINITIONS)} strata.")
    
    overlap_count = sum(1 for item in sample if item.get("is_overlap"))
    print(f"[*] Overlap items designated for double-blind review: {overlap_count}")
    
    # Write to data/groundtruth/label_queue.jsonl and root label_queue.jsonl
    out_dir = Path("data/groundtruth")
    out_dir.mkdir(parents=True, exist_ok=True)
    queue_file = out_dir / "label_queue.jsonl"
    root_queue_file = Path("label_queue.jsonl")
    
    with open(queue_file, "w", encoding="utf-8") as f, open(root_queue_file, "w", encoding="utf-8") as rf:
        for item in sample:
            line = json.dumps(item) + "\n"
            f.write(line)
            rf.write(line)
            
    print(f"[✓] Written {len(sample)} queue items to {queue_file} and {root_queue_file}")
    
    # Generate label_template.csv with empty annotations ready for human annotators
    template_file = out_dir / "label_template.csv"
    with open(template_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["item_id", "server_id", "tool_name", "label", "evidence_path", "labeler_id", "timestamp", "confidence"])
        # Primary 100 items
        for item in sample:
            writer.writerow([
                item["item_id"],
                item["server_id"],
                item["tool_name"],
                "",  # label (vuln|clean) to be filled by human
                "",  # evidence_path to be filled by human
                "annotator_alpha",
                "",  # timestamp
                "",  # confidence (1-3)
            ])
        # 20 Overlap items for annotator_beta
        for item in sample:
            if item.get("is_overlap"):
                writer.writerow([
                    item["item_id"],
                    item["server_id"],
                    item["tool_name"],
                    "",  # label (vuln|clean) to be filled by human
                    "",  # evidence_path to be filled by human
                    "annotator_beta",
                    "",  # timestamp
                    "",  # confidence (1-3)
                ])

    print(f"[✓] Initialized {template_file} with 120 annotation slots (100 primary + 20 overlap)")

if __name__ == "__main__":
    main()
