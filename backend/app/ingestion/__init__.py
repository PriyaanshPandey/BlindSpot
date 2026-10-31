"""
Ingestion subsystem [Role A]:
Responsible for parsing declared dependencies (package.json, composer.json, Dockerfile, Terraform)
and observed evidence (OpenTelemetry traces, DNS logs, browser crawls).
"""
import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger("hdx.ingestion")

def parse_package_json(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return {"name": data.get("name", "unknown"), "dependencies": deps}

def parse_runtime_traces(trace_file_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(trace_file_path):
        return []
    with open(trace_file_path, "r", encoding="utf-8") as f:
        return json.load(f)

