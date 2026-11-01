"""
Ingestion subsystem [Role A]:
Deeply and recursively discovers dependencies, packages, lockfiles, infrastructure services,
environment integrations, and third-party API connections across ANY local project or nested directory structure.
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
    "firebase": {"vendor": "Firebase (Google Cloud)", "host": "firebase.google.com", "category": "backend_platform", "upstream": ["google-cloud-us-central1"]},
    "razorpay": {"vendor": "Razorpay Payments", "host": "api.razorpay.com", "category": "payment_gateway", "upstream": ["aws-ap-south-1", "cloudflare-edge"]},
    "stripe": {"vendor": "Stripe Payments", "host": "api.stripe.com", "category": "payment_gateway", "upstream": ["aws-us-east-1", "cloudflare-edge"]},
    "paypal": {"vendor": "PayPal Payments", "host": "api.paypal.com", "category": "payment_gateway", "upstream": ["azure-eastus", "fastly-cdn"]},
    "supabase": {"vendor": "Supabase Platform", "host": "supabase.co", "category": "database_backend", "upstream": ["aws-eu-central-1"]},
    "openai": {"vendor": "OpenAI API", "host": "api.openai.com", "category": "ai_inference", "upstream": ["azure-openai-eastus"]},
    "gemini": {"vendor": "Google Gemini AI", "host": "generativelanguage.googleapis.com", "category": "ai_inference", "upstream": ["google-tpu-cluster"]},
    "groq": {"vendor": "Groq AI Cloud", "host": "api.groq.com", "category": "ai_inference", "upstream": ["aws-us-east-1"]},
    "rapidapi": {"vendor": "RapidAPI Gateway", "host": "rapidapi.com", "category": "api_marketplace", "upstream": ["aws-us-east-1", "cloudflare-edge"]},
    "jsearch": {"vendor": "RapidAPI Gateway", "host": "rapidapi.com", "category": "api_marketplace", "upstream": ["aws-us-east-1"]},
    "auth0": {"vendor": "Auth0 Identity", "host": "auth0.com", "category": "identity_provider", "upstream": ["aws-global-idp", "fastly-cdn"]},
    "clerk": {"vendor": "Clerk Authentication", "host": "clerk.dev", "category": "identity_provider", "upstream": ["aws-us-east-1", "cloudflare-edge"]},
    "linkedin": {"vendor": "LinkedIn OAuth / API", "host": "api.linkedin.com", "category": "identity_provider", "upstream": ["azure-eastus"]},
    "github": {"vendor": "GitHub API", "host": "api.github.com", "category": "developer_platform", "upstream": ["azure-eastus", "fastly-cdn"]},
    "twilio": {"vendor": "Twilio Communications", "host": "api.twilio.com", "category": "telecom_sms", "upstream": ["aws-us-east-1"]},
    "sendgrid": {"vendor": "Twilio SendGrid", "host": "api.sendgrid.com", "category": "email_dispatch", "upstream": ["aws-us-east-1"]},
    "postmark": {"vendor": "Postmark Email", "host": "api.postmarkapp.com", "category": "email_dispatch", "upstream": ["aws-us-east-1"]},
    "resend": {"vendor": "Resend Email", "host": "api.resend.com", "category": "email_dispatch", "upstream": ["aws-us-east-1"]},
    "sentry": {"vendor": "Sentry Error Monitoring", "host": "sentry.io", "category": "observability", "upstream": ["google-cloud-us-central1"]},
    "mixpanel": {"vendor": "Mixpanel Analytics", "host": "api.mixpanel.com", "category": "product_analytics", "upstream": ["google-cloud-us-central1"]},
    "segment": {"vendor": "Segment Analytics", "host": "telemetry.segment.io", "category": "product_analytics", "upstream": ["aws-us-west-2"]},
    "algolia": {"vendor": "Algolia Search", "host": "latency-dsn.algolia.net", "category": "search_infrastructure", "upstream": ["aws-multi-region"]},
    "veriff": {"vendor": "Veriff KYC", "host": "api.veriff.com", "category": "identity_kyc", "upstream": ["aws-eu-west-1"]},
    "plaid": {"vendor": "Plaid Banking", "host": "api.plaid.com", "category": "fintech_banking", "upstream": ["aws-us-east-1"]},
    "sift": {"vendor": "Sift Fraud Prevention", "host": "api.sift.com", "category": "fraud_security", "upstream": ["aws-us-west-2"]},
    "cloudinary": {"vendor": "Cloudinary CDN", "host": "api.cloudinary.com", "category": "media_cdn", "upstream": ["aws-us-east-1", "fastly-cdn"]},
    "gmail": {"vendor": "Google Gmail SMTP", "host": "smtp.gmail.com", "category": "email_dispatch", "upstream": ["google-cloud-us-central1"]},
    "aws": {"vendor": "Amazon Web Services (AWS)", "host": "amazonaws.com", "category": "cloud_infrastructure", "upstream": []},
    "cloudflare": {"vendor": "Cloudflare Edge", "host": "cloudflare.com", "category": "cdn_ddos", "upstream": []}
}

KNOWN_INFRASTRUCTURE = {
    "mongodb": {"name": "MongoDB Database", "category": "database", "keywords": ["mongo"]},
    "redis": {"name": "Redis Cache / Queue", "category": "cache_queue", "keywords": ["redis"]},
    "postgres": {"name": "PostgreSQL Database", "category": "database", "keywords": ["postgres", "pgsql"]},
    "mysql": {"name": "MySQL Database", "category": "database", "keywords": ["mysql", "mariadb"]},
    "rabbitmq": {"name": "RabbitMQ Message Broker", "category": "message_broker", "keywords": ["rabbit", "amqp"]},
}

KNOWN_NODE_TRANSITIVES = {
    # 3rd-Party -> 4th-Party Transitives
    "event-stream": {"flatmap-stream": "0.1.1"},
    "express": {"body-parser": "1.20.2", "cookie": "0.6.0", "send": "0.18.0", "serve-static": "1.15.0"},
    "axios": {"follow-redirects": "1.15.6", "form-data": "4.0.0"},
    "jsonwebtoken": {"jws": "3.2.2", "ms": "2.1.3", "semver": "7.5.4"},
    "react-dom": {"scheduler": "0.23.0"},
    "next": {"styled-jsx": "5.1.1", "@next/env": "14.1.0"},
    "nodemon": {"chokidar": "3.5.3", "debug": "4.3.4"},
    # 4th-Party -> 5th-Party Deep Transitives
    "body-parser": {"raw-body": "2.4.0", "bytes": "3.1.2", "iconv-lite": "0.4.24"},
    "send": {"mime": "1.6.0", "fresh": "0.5.2"},
    "jws": {"jwa": "2.0.0"},
    "chokidar": {"anymatch": "3.1.3", "braces": "3.0.2"}
}

KNOWN_PYTHON_TRANSITIVES = {
    # 3rd-Party -> 4th-Party
    "celery": {"kombu": "5.3.4", "billiard": "4.2.0"},
    "django": {"asgiref": "3.7.2", "sqlparse": "0.4.4"},
    "requests": {"urllib3": "1.26.18", "certifi": "2023.11.17"},
    "fastapi": {"starlette": "0.27.0", "pydantic-core": "2.14.5"},
    "stripe": {"urllib3": "1.26.18"},
    "flask": {"werkzeug": "2.3.8", "jinja2": "3.1.2"},
    "redis": {"async-timeout": "4.0.3"},
    # 4th-Party -> 5th-Party
    "kombu": {"amqp": "5.2.0", "vine": "5.0.0"},
    "urllib3": {"idna": "3.6"},
    "starlette": {"anyio": "3.7.1"}
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

def extract_clean_pkg_name(pkg_path: str) -> str:
    """
    Extracts canonical package name from node_modules path.
    Handles scoped packages (@medusajs/medusa, @types/node) as well as standard packages.
    """
    if not pkg_path:
        return ""
    clean = pkg_path.strip("/")
    if "node_modules/" in clean:
        clean = clean.split("node_modules/")[-1].strip("/")
    return clean

def extract_package_lock_dependencies(data: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """
    Parses package-lock.json (v1, v2, v3) into parent -> {child: version} mapping.
    Handles both packages (v2/v3) and dependencies (v1) structures.
    """
    results: Dict[str, Dict[str, str]] = {}
    if not isinstance(data, dict):
        return results

    # Support npm lockfile v2 & v3 (packages object)
    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for pkg_path, pkg_info in packages.items():
            if not pkg_path or not isinstance(pkg_info, dict):
                continue
            parent_name = extract_clean_pkg_name(pkg_path)
            if not parent_name:
                continue
            child_deps = pkg_info.get("dependencies", {})
            if isinstance(child_deps, dict) and child_deps:
                results.setdefault(parent_name, {}).update(child_deps)

    # Support npm lockfile v1 (dependencies object)
    dependencies = data.get("dependencies", {})
    if isinstance(dependencies, dict):
        for parent_name, parent_info in dependencies.items():
            if not isinstance(parent_info, dict):
                continue
            child_deps = parent_info.get("dependencies", {})
            if isinstance(child_deps, dict):
                for child_name, child_meta in child_deps.items():
                    ver = child_meta.get("version", "*") if isinstance(child_meta, dict) else str(child_meta)
                    results.setdefault(parent_name, {})[child_name] = ver

    return results

def parse_package_lock_json(file_path: str) -> Dict[str, Dict[str, str]]:
    """
    Parses package-lock.json from disk to extract true parent-child transitive dependencies.
    """
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return extract_package_lock_dependencies(data)
    except Exception as e:
        logger.warning(f"Failed to parse lockfile at {file_path}: {e}")
        return {}

def resolve_multi_tier_transitives(
    direct_deps: Dict[str, str],
    lock_data_map: Dict[str, Dict[str, str]]
) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, str]]]:
    """
    Resolves multi-tier transitive trees (2-3 layers deep):
      Tier 2: Transitive dependencies of direct packages
      Tier 3: Deep transitive dependencies of Tier 2 packages
    Returns (layer_2_transitives, layer_3_deep_transitives)
    """
    layer_2: Dict[str, Dict[str, str]] = {}
    layer_3: Dict[str, Dict[str, str]] = {}

    # Layer 2: Direct -> Transitive
    for direct_pkg in direct_deps:
        # Check lockfile first
        children = lock_data_map.get(direct_pkg)
        if not children:
            clean_p = direct_pkg.lower()
            children = KNOWN_NODE_TRANSITIVES.get(clean_p) or KNOWN_PYTHON_TRANSITIVES.get(clean_p)

        if children:
            layer_2[direct_pkg] = dict(children)

    # Layer 3: Transitive -> Deep Transitive (3rd layer)
    for direct_pkg, sub_dict in layer_2.items():
        for sub_pkg in sub_dict:
            if sub_pkg in layer_3:
                continue
            deep_children = lock_data_map.get(sub_pkg)
            if not deep_children:
                clean_s = sub_pkg.lower()
                deep_children = KNOWN_NODE_TRANSITIVES.get(clean_s) or KNOWN_PYTHON_TRANSITIVES.get(clean_s)

            if deep_children:
                layer_3[sub_pkg] = dict(deep_children)

    return layer_2, layer_3

def parse_docker_compose_services(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses docker-compose.yml to discover declared infrastructure (databases, caches, queues).
    """
    if not os.path.exists(file_path):
        return []
    infra_nodes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        service_blocks = re.findall(r'(\b[a-zA-Z0-9_-]+):\s*\n(?:\s+image:\s*([^\n]+))?', content)
        for s_name, image in service_blocks:
            lower_name = s_name.lower()
            lower_image = (image or "").lower()
            infra_type = None
            if any(k in lower_name or k in lower_image for k in ["postgres", "pgsql"]):
                infra_type = "PostgreSQL Database"
            elif any(k in lower_name or k in lower_image for k in ["redis", "cache"]):
                infra_type = "Redis Cache & Queue"
            elif any(k in lower_name or k in lower_image for k in ["mongo"]):
                infra_type = "MongoDB Document Store"
            elif any(k in lower_name or k in lower_image for k in ["mysql", "mariadb"]):
                infra_type = "MySQL Relational Database"
            elif any(k in lower_name or k in lower_image for k in ["rabbit", "mq"]):
                infra_type = "RabbitMQ Message Broker"

            if infra_type:
                infra_nodes.append({
                    "id": f"infra:{s_name}",
                    "name": f"{s_name.capitalize()} ({infra_type})",
                    "category": "database" if "database" in infra_type.lower() or "store" in infra_type.lower() else "cache_queue",
                    "image": image.strip() if image else "latest"
                })
    except Exception as e:
        logger.warning(f"Failed to parse docker-compose at {file_path}: {e}")
    return infra_nodes

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

def extract_infrastructure_from_env(env_path: str) -> List[Dict[str, Any]]:
    infras = []
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                upper = clean.upper()
                for key, info in KNOWN_INFRASTRUCTURE.items():
                    if any(kw.upper() in upper for kw in info["keywords"]):
                        inf_id = f"infra:{key}"
                        if not any(x["id"] == inf_id for x in infras):
                            infras.append({
                                "id": inf_id,
                                "name": info["name"],
                                "category": info["category"],
                                "image": "latest"
                            })
    except Exception:
        pass
    return infras

def extract_cloud_services_from_env(env_path: str) -> List[Tuple[str, str]]:
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
    - Collects real direct packages
    - Extracts transitive dependency trees from lockfiles
    - Detects infrastructure (databases, caches, message queues) from docker-compose
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
    transitive_dependencies: Dict[str, Dict[str, str]] = {}
    infrastructure_nodes: List[Dict[str, Any]] = []
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

            # 1. Package Manifests & Lockfiles
            if lower_file == "package.json":
                pkg_data = parse_package_json(file_path)
                if pkg_data.get("name") and project_name in [os.path.basename(abs_path), "Unnamed Project"]:
                    project_name = pkg_data["name"]
                d = pkg_data.get("dependencies", {})
                services[subservice_key]["dependencies"].update(d)
                services[subservice_key]["ecosystem"] = "npm"
                overall_dependencies.update(d)

            elif lower_file in ["package-lock.json", "npm-shrinkwrap.json"]:
                lock_trans = parse_package_lock_json(file_path)
                for parent, children in lock_trans.items():
                    transitive_dependencies.setdefault(parent, {}).update(children)

            elif lower_file in ["docker-compose.yml", "docker-compose.yaml"]:
                infra_found = parse_docker_compose_services(file_path)
                for inf in infra_found:
                    if not any(x["id"] == inf["id"] for x in infrastructure_nodes):
                        infrastructure_nodes.append(inf)

            elif lower_file in ["requirements.txt", "pipfile"]:
                py_deps = parse_requirements_txt(file_path)
                services[subservice_key]["dependencies"].update(py_deps)
                services[subservice_key]["ecosystem"] = "PyPI"
                overall_dependencies.update(py_deps)

            # 2. Environment Integrations
            elif lower_file == ".env" or lower_file.startswith(".env."):
                env_infras = extract_infrastructure_from_env(file_path)
                for einf in env_infras:
                    if not any(x["id"] == einf["id"] for x in infrastructure_nodes):
                        infrastructure_nodes.append(einf)

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

    # Multi-tier transitive resolution: 2nd layer & 3rd layer deep transitives
    layer_2_trans, layer_3_deep = resolve_multi_tier_transitives(overall_dependencies, transitive_dependencies)

    return {
        "project_name": project_name,
        "folder_path": abs_path,
        "services": services,
        "dependencies": overall_dependencies,
        "transitive_dependencies": layer_2_trans,
        "deep_transitive_dependencies": layer_3_deep,
        "infrastructure_nodes": infrastructure_nodes,
        "observed_hosts": list(observed_hosts),
        "evidence_records": evidence_records,
        "source_files_scanned": source_files_scanned
    }

def parse_runtime_traces(trace_file_path: str) -> List[Dict[str, Any]]:
    if not trace_file_path or not os.path.exists(trace_file_path):
        return []
    try:
        with open(trace_file_path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return []
