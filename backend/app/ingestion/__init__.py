"""
Ingestion subsystem [Role A]:
Deeply and recursively discovers dependencies, packages, environment integrations,
and third-party API connections across ANY local project or nested directory structure.
"""
import os
import re
import json
import logging
from typing import Dict, Any, List, Set, Tuple

logger = logging.getLogger("hdx.ingestion")

URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>)]*)?')
IMPORT_REGEX = re.compile(r"(?:import\s+.*?from\s+['\"]([^'\"./][^'\"]*)['\"]|require\(['\"]([^'\"./][^'\"]*)['\"]\))")

EXCLUDED_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".idea", ".vscode", "coverage"}

KNOWN_CLOUD_VENDORS = {
    "firebase": {"vendor": "Firebase (Google Cloud)", "host": "firebase.google.com", "category": "auth_database"},
    "razorpay": {"vendor": "Razorpay Payments", "host": "api.razorpay.com", "category": "payment_gateway"},
    "stripe": {"vendor": "Stripe Payments", "host": "api.stripe.com", "category": "payment_gateway"},
    "paypal": {"vendor": "PayPal Payments", "host": "api.paypal.com", "category": "payment_gateway"},
    "supabase": {"vendor": "Supabase Platform", "host": "supabase.co", "category": "database_backend"},
    "openai": {"vendor": "OpenAI API", "host": "api.openai.com", "category": "ai_inference"},
    "gemini": {"vendor": "Google Gemini AI", "host": "generativelanguage.googleapis.com", "category": "ai_inference"},
    "rapidapi": {"vendor": "RapidAPI Gateway", "host": "rapidapi.com", "category": "api_marketplace"},
    "jsearch": {"vendor": "JSearch (RapidAPI)", "host": "jsearch.p.rapidapi.com", "category": "external_api"},
    "auth0": {"vendor": "Auth0 Identity", "host": "auth0.com", "category": "identity_provider"},
    "twilio": {"vendor": "Twilio Communications", "host": "api.twilio.com", "category": "telecom_sms"},
    "sendgrid": {"vendor": "Twilio SendGrid", "host": "api.sendgrid.com", "category": "email_dispatch"},
    "postmark": {"vendor": "Postmark Email", "host": "api.postmarkapp.com", "category": "email_dispatch"},
    "sentry": {"vendor": "Sentry Error Monitoring", "host": "sentry.io", "category": "observability"},
    "mixpanel": {"vendor": "Mixpanel Analytics", "host": "api.mixpanel.com", "category": "product_analytics"},
    "segment": {"vendor": "Segment Analytics", "host": "telemetry.segment.io", "category": "product_analytics"},
    "algolia": {"vendor": "Algolia Search", "host": "latency-dsn.algolia.net", "category": "search_infrastructure"},
    "veriff": {"vendor": "Veriff KYC", "host": "api.veriff.com", "category": "identity_kyc"},
    "plaid": {"vendor": "Plaid Banking", "host": "api.plaid.com", "category": "fintech_banking"},
    "sift": {"vendor": "Sift Fraud Prevention", "host": "api.sift.com", "category": "fraud_security"},
    "mongodb": {"vendor": "MongoDB Database", "host": "mongodb-cluster", "category": "database"},
    "redis": {"vendor": "Redis Cache / Queue", "host": "redis-cluster", "category": "cache_queue"},
    "postgres": {"vendor": "PostgreSQL Database", "host": "postgresql-cluster", "category": "database"},
    "mysql": {"vendor": "MySQL Database", "host": "mysql-cluster", "category": "database"},
    "aws": {"vendor": "Amazon Web Services (AWS)", "host": "amazonaws.com", "category": "cloud_infrastructure"},
    "cloudflare": {"vendor": "Cloudflare Edge", "host": "cloudflare.com", "category": "cdn_ddos"}
}

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

def extract_cloud_services_from_env(env_path: str) -> List[Tuple[str, str]]:
    """Returns list of (service_host, evidence_line)."""
    results = []
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                upper = clean_line.upper()
                for key, info in KNOWN_CLOUD_VENDORS.items():
                    if key.upper() in upper:
                        results.append((info["host"], f"{os.path.basename(env_path)}: {clean_line.split('=')[0]}"))
    except Exception:
        pass
    return results

def scan_project_directory(folder_path: str) -> Dict[str, Any]:
    """
    Scans ANY local repository or folder and builds true architectural model:
    - Detects root project and subservices (frontend, backend, worker, api)
    - Collects real npm, python, and go dependencies mapped to their subservice
    - Extracts real third-party endpoints and vendor services
    """
    abs_path = os.path.abspath(folder_path)
    if not os.path.exists(abs_path):
        return {"error": f"Path '{folder_path}' does not exist on disk."}

    project_name = os.path.basename(abs_path)
    services: Dict[str, Dict[str, Any]] = {
        "core": {
            "name": f"{project_name} Core",
            "type": "internal_service",
            "path": abs_path,
            "dependencies": {},
            "ecosystem": "npm",
            "external_calls": set()
        }
    }
    
    overall_dependencies: Dict[str, str] = {}
    observed_hosts: Set[str] = set()
    evidence_records: Dict[str, List[str]] = {}
    source_files_scanned = 0

    SCANNABLE_EXTS = {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".env", ".yaml", ".yml"}

    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        rel_dir = os.path.relpath(root, abs_path).lower().replace("\\", "/")

        # Subservice detection
        subservice_key = "core"
        if "backend" in rel_dir or "server" in rel_dir or "api" in rel_dir:
            subservice_key = "backend"
        elif "frontend" in rel_dir or "client" in rel_dir or "web" in rel_dir or "ui" in rel_dir:
            subservice_key = "frontend"

        if subservice_key not in services:
            services[subservice_key] = {
                "name": f"{project_name} {subservice_key.capitalize()} Service",
                "type": "internal_service",
                "path": root,
                "dependencies": {},
                "ecosystem": "npm",
                "external_calls": set()
            }

        for file in files:
            file_path = os.path.join(root, file)
            lower_file = file.lower()
            rel_file = os.path.relpath(file_path, abs_path)

            # 1. Package Manifests
            if lower_file == "package.json":
                pkg_data = parse_package_json(file_path)
                if pkg_data.get("name") and project_name in [os.path.basename(abs_path), "Unnamed Project"]:
                    project_name = pkg_data["name"]
                d = pkg_data.get("dependencies", {})
                services[subservice_key]["dependencies"].update(d)
                services[subservice_key]["ecosystem"] = "npm"
                overall_dependencies.update(d)

            elif lower_file in ["requirements.txt", "pipfile"]:
                py_deps = parse_requirements_txt(file_path)
                services[subservice_key]["dependencies"].update(py_deps)
                services[subservice_key]["ecosystem"] = "PyPI"
                overall_dependencies.update(py_deps)

            # 2. Environment Integrations
            elif lower_file == ".env" or lower_file.startswith(".env."):
                env_svcs = extract_cloud_services_from_env(file_path)
                for host, ev in env_svcs:
                    observed_hosts.add(host)
                    services[subservice_key]["external_calls"].add(host)
                    evidence_records.setdefault(host, []).append(f"{rel_file} ({ev})")

            # 3. Source Code Scanning
            ext = os.path.splitext(file)[1].lower()
            if ext in SCANNABLE_EXTS:
                source_files_scanned += 1
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(100000)

                    # Extract URLs
                    matches = URL_REGEX.findall(content)
                    for m in matches:
                        host_match = re.search(r'https?://([^/:\s]+)', m)
                        if host_match:
                            host = host_match.group(1).lower()
                            if not host.startswith(("localhost", "127.0.0.1")) and not host.endswith(("schema.org", "w3.org", "github.com", "npmjs.org")):
                                observed_hosts.add(host)
                                services[subservice_key]["external_calls"].add(host)
                                evidence_records.setdefault(host, []).append(f"{rel_file}")

                    # Extract JS/TS imports
                    if ext in [".js", ".jsx", ".ts", ".tsx"]:
                        import_matches = IMPORT_REGEX.findall(content)
                        for imp in import_matches:
                            raw_pkg = imp[0] or imp[1]
                            if raw_pkg and not raw_pkg.startswith("."):
                                root_pkg = raw_pkg.split("/")[0]
                                if root_pkg not in ["react", "react-dom"] and root_pkg not in overall_dependencies:
                                    services[subservice_key]["dependencies"][root_pkg] = "latest"
                                    overall_dependencies[root_pkg] = "latest"
                except Exception:
                    continue

    return {
        "project_name": project_name,
        "folder_path": abs_path,
        "services": services,
        "dependencies": overall_dependencies,
        "observed_hosts": list(observed_hosts),
        "evidence_records": evidence_records,
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
