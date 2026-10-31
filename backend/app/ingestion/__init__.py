"""
Ingestion subsystem [Role A]:
Deeply and recursively discovers dependencies, packages, environment integrations,
and third-party API connections across ANY local project or nested directory structure.
"""
import os
import re
import json
import logging
from typing import Dict, Any, List, Set

logger = logging.getLogger("hdx.ingestion")

URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>)]*)?')
IMPORT_REGEX = re.compile(r"(?:import\s+.*?from\s+['\"]([^'\"./][^'\"]*)['\"]|require\(['\"]([^'\"./][^'\"]*)['\"]\))")

EXCLUDED_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".idea", ".vscode"}

def parse_package_json(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        return {"name": data.get("name", ""), "dependencies": deps}
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

def extract_cloud_services_from_env(env_path: str) -> List[str]:
    """Extracts configured cloud integrations and vendor endpoints from .env files."""
    services = []
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                upper = line.upper()
                if "FIREBASE" in upper:
                    services.append("firebase.google.com")
                elif "RAZORPAY" in upper:
                    services.append("api.razorpay.com")
                elif "RAPID" in upper or "JSEARCH" in upper:
                    services.append("jsearch.p.rapidapi.com")
                elif "LINKEDIN" in upper:
                    services.append("api.linkedin.com")
                elif "STRIPE" in upper:
                    services.append("api.stripe.com")
                elif "AUTH0" in upper:
                    services.append("auth0.com")
                elif "TWILIO" in upper:
                    services.append("api.twilio.com")
                elif "SENDGRID" in upper:
                    services.append("api.sendgrid.com")
                elif "SMTP_HOST" in upper:
                    val = line.split("=", 1)[1].strip() if "=" in line else ""
                    if val and "smtp" in val.lower():
                        services.append(val.lower())
                elif "MONGODB" in upper:
                    services.append("mongodb-cluster")
                elif "REDIS" in upper:
                    services.append("redis-cache")
                elif "GEMINI" in upper or "OPENAI" in upper or "ANTHROPIC" in upper:
                    services.append("generativelanguage.googleapis.com")
    except Exception:
        pass
    return services

def scan_project_directory(folder_path: str) -> Dict[str, Any]:
    """
    Recursively scans ANY local directory:
    - Finds all package.json files (even nested in monorepos or subdirectories)
    - Finds all requirements.txt / pyproject.toml
    - Discovers external cloud APIs in .env files (Firebase, Razorpay, RapidAPI, Stripe, etc.)
    - Analyzes code imports and external HTTP/HTTPS endpoints
    """
    abs_path = os.path.abspath(folder_path)
    if not os.path.exists(abs_path):
        return {"error": f"Path '{folder_path}' does not exist on disk."}

    project_name = os.path.basename(abs_path)
    dependencies: Dict[str, str] = {}
    observed_hosts: Set[str] = set()
    code_discovered_packages: Set[str] = set()
    source_files_scanned = 0

    SCANNABLE_EXTS = {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".env"}

    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        
        for file in files:
            file_path = os.path.join(root, file)
            lower_file = file.lower()

            # 1. Recursive Package Manifests
            if lower_file == "package.json":
                pkg_data = parse_package_json(file_path)
                if pkg_data.get("name") and project_name in [os.path.basename(abs_path), "Unnamed Project"]:
                    project_name = pkg_data["name"]
                dependencies.update(pkg_data.get("dependencies", {}))

            elif lower_file in ["requirements.txt", "pipfile"]:
                py_deps = parse_requirements_txt(file_path)
                dependencies.update(py_deps)

            # 2. Environment Configurations
            elif lower_file == ".env" or lower_file.startswith(".env."):
                env_services = extract_cloud_services_from_env(file_path)
                for svc in env_services:
                    observed_hosts.add(svc)

            # 3. Code Imports and External URLs
            ext = os.path.splitext(file)[1].lower()
            if ext in SCANNABLE_EXTS:
                source_files_scanned += 1
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(100000)

                    # Extract external URLs
                    matches = URL_REGEX.findall(content)
                    for m in matches:
                        host_match = re.search(r'https?://([^/:\s]+)', m)
                        if host_match:
                            host = host_match.group(1).lower()
                            if not host.startswith(("localhost", "127.0.0.1")) and not host.endswith(("schema.org", "w3.org")):
                                observed_hosts.add(host)

                    # Extract package imports if JavaScript/TypeScript
                    if ext in [".js", ".jsx", ".ts", ".tsx"]:
                        import_matches = IMPORT_REGEX.findall(content)
                        for imp in import_matches:
                            raw_pkg = imp[0] or imp[1]
                            if raw_pkg and not raw_pkg.startswith("."):
                                root_pkg = raw_pkg.split("/")[0]
                                code_discovered_packages.add(root_pkg)
                except Exception:
                    continue

    # Merge code discovered packages if not declared in manifest
    for c_pkg in code_discovered_packages:
        if c_pkg not in dependencies and c_pkg not in ["react", "react-dom"]:
            dependencies[c_pkg] = "latest"

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
