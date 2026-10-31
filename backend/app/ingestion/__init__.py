"""
Ingestion subsystem [Role A]:
Responsible for parsing declared dependencies (package.json, requirements.txt, Dockerfile, Terraform)
and scanning project source files to discover real observed external connections and APIs.
"""
import os
import re
import json
import logging
from typing import Dict, Any, List, Set

logger = logging.getLogger("hdx.ingestion")

URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>)]*)?')

def parse_package_json(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        return {"name": data.get("name", "Unnamed Project"), "dependencies": deps}
    except Exception as e:
        logger.warning(f"Failed to parse package.json at {file_path}: {e}")
        return {}

def parse_requirements_txt(file_path: str) -> Dict[str, str]:
    if not os.path.exists(file_path):
        return {}
    deps = {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r'==|>=|<=|~=', line)
                    pkg = parts[0].strip()
                    ver = parts[1].strip() if len(parts) > 1 else "*"
                    deps[pkg] = ver
    except Exception as e:
        logger.warning(f"Failed to parse requirements.txt at {file_path}: {e}")
    return deps

def scan_project_directory(folder_path: str) -> Dict[str, Any]:
    """
    Recursively scans any local folder:
    - Finds manifest files (package.json, requirements.txt)
    - Extracts observed external network calls (script src, fetch, axios, webhook URLs)
    """
    abs_path = os.path.abspath(folder_path)
    if not os.path.exists(abs_path):
        return {"error": f"Path '{folder_path}' does not exist on disk."}

    project_name = os.path.basename(abs_path)
    dependencies: Dict[str, str] = {}
    observed_hosts: Set[str] = set()
    source_files_scanned = 0

    # 1. Look for package.json
    pkg_path = os.path.join(abs_path, "package.json")
    if os.path.exists(pkg_path):
        pkg_data = parse_package_json(pkg_path)
        if pkg_data.get("name") and pkg_data["name"] != "Unnamed Project":
            project_name = pkg_data["name"]
        dependencies.update(pkg_data.get("dependencies", {}))

    # 2. Look for requirements.txt
    req_path = os.path.join(abs_path, "requirements.txt")
    if os.path.exists(req_path):
        py_deps = parse_requirements_txt(req_path)
        dependencies.update(py_deps)

    # 3. Scan code files for external endpoints (HTML script tags, fetch, axios, etc.)
    EXCLUDED_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__"}
    SCANNABLE_EXTS = {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".env"}

    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SCANNABLE_EXTS:
                file_path = os.path.join(root, file)
                source_files_scanned += 1
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(50000)  # read first 50KB
                        matches = URL_REGEX.findall(content)
                        for m in matches:
                            host_match = re.search(r'https?://([^/:\s]+)', m)
                            if host_match:
                                host = host_match.group(1).lower()
                                if not host.startswith("localhost") and not host.startswith("127.0.0.1") and not host.endswith("schema.org") and not host.endswith("w3.org"):
                                    observed_hosts.add(host)
                except Exception:
                    continue

    return {
        "project_name": project_name,
        "folder_path": abs_path,
        "dependencies": dependencies,
        "observed_hosts": list(observed_hosts),
        "source_files_scanned": source_files_scanned
    }

def parse_runtime_traces(trace_file_path: str) -> List[Dict[str, Any]]:
    if not trace_file_path or not os.path.exists(trace_file_path):
        return []
    try:
        with open(trace_file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []
