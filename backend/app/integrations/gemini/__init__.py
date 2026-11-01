from app.integrations.gemini.grounding import resolve_authoritative_advisory, validate_and_ground_explanation
"""
Workstream D: Google Gemini API Integration
Implements privacy-preserving structured explanations for vulnerabilities and dependency relationships.
Complies strictly with data privacy boundaries: no source code, no secrets, no private traces.
Uses the official google-genai SDK.
"""
import os
import re
import json
import logging
import asyncio
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

from google.genai import Client
from google.genai.errors import APIError, ClientError, ServerError

from app.core.config import settings

logger = logging.getLogger("hdx.gemini")

# Automatically load .env from multiple potential locations
root_dir = Path(__file__).resolve().parent.parent.parent.parent
load_dotenv(root_dir / ".env")
load_dotenv(root_dir / "backend" / ".env")

# Model identifier configuration
DEFAULT_GEMINI_MODEL = getattr(settings, "GEMINI_MODEL", None) or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

# Error status constants required by the UX & API contract
STATUS_AI_READY = "AI_READY"
STATUS_AI_NOT_CONFIGURED = "AI_NOT_CONFIGURED"
STATUS_AI_UNAVAILABLE_OFFLINE = "AI_UNAVAILABLE_OFFLINE"
STATUS_AI_AUTH_FAILED = "AI_AUTH_FAILED"
STATUS_AI_QUOTA_EXCEEDED = "AI_QUOTA_EXCEEDED"
STATUS_AI_MODEL_UNAVAILABLE = "AI_MODEL_UNAVAILABLE"
STATUS_AI_REQUEST_FAILED = "AI_REQUEST_FAILED"

# Canary regex patterns for secrets and private information that must never leak
SENSITIVE_PATTERNS = [
    re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{16,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    re.compile(r"AIza[0-9A-Za-z-_]{35}", re.IGNORECASE),
    re.compile(r"(?:password|passwd|pwd|secret|token)\s*[:=]\s*['\"]?[^\s'\"]+", re.IGNORECASE),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),  # IP addresses
    re.compile(r"(?:[A-Za-z]:\\|/(?:home|Users|internal|etc|var|usr|root)/)[^\s'\"]+"), # Absolute paths
]


def get_gemini_api_key(override_key: Optional[str] = None) -> str:
    """
    Safely retrieves the configured Gemini API key without exposing it.
    Checks explicit parameter first, then settings / os.environ.
    """
    if override_key and override_key.strip():
        return override_key.strip()
    key = getattr(settings, "GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    return key.strip()


import time

_STATUS_CACHE: Dict[str, Any] = {
    "data": None,
    "timestamp": 0.0,
    "key_hash": None,
    "model": None
}
_STATUS_CACHE_TTL_SECONDS = 30.0


def update_gemini_status_cache(status_code: str, message: str, model: str):
    """Updates the shared in-memory status cache when live operations complete."""
    _STATUS_CACHE["data"] = {
        "status": status_code,
        "configured": status_code != STATUS_AI_NOT_CONFIGURED,
        "model": model,
        "message": message,
        "checked_at": time.time()
    }
    _STATUS_CACHE["timestamp"] = time.time()
    _STATUS_CACHE["model"] = model


def check_gemini_status(api_key: Optional[str] = None, force_refresh: bool = False) -> Dict[str, Any]:
    """
    Authoritative single-source status verification for Google Gemini:
    - AI_NOT_CONFIGURED: API key missing.
    - AI_READY: API key valid, network reachable, and configured model verified available via lightweight metadata check.
    - AI_AUTH_FAILED: Google rejected API key (401/403/API_KEY_INVALID).
    - AI_QUOTA_EXCEEDED: Quota/rate-limit reached (429/RESOURCE_EXHAUSTED).
    - AI_MODEL_UNAVAILABLE: Configured model not found (404/NOT_FOUND).
    - AI_UNAVAILABLE_OFFLINE: Network down, timeout, or transient 503.
    - AI_REQUEST_FAILED: Other unexpected error.
    Uses lightweight model metadata check (client.models.get) with 30s caching.
    """
    model_name = getattr(settings, "GEMINI_MODEL", None) or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
    key = get_gemini_api_key(api_key)
    if not key:
        return {
            "status": STATUS_AI_NOT_CONFIGURED,
            "configured": False,
            "model": model_name,
            "message": "GEMINI_API_KEY is not configured in backend environment or request."
        }

    now = time.time()
    key_hash = hash(key)
    if (
        not force_refresh
        and _STATUS_CACHE["data"] is not None
        and _STATUS_CACHE["key_hash"] == key_hash
        and _STATUS_CACHE["model"] == model_name
        and (now - _STATUS_CACHE["timestamp"] < _STATUS_CACHE_TTL_SECONDS)
    ):
        return _STATUS_CACHE["data"]

    # Perform lightweight model metadata/availability verification
    try:
        from google import genai
        from google.genai.errors import APIError

        client = genai.Client(api_key=key)
        # Lightweight metadata GET: 0 tokens generated, non-destructive, verifies auth + model availability + network
        model_info = client.models.get(model=model_name)
        display = getattr(model_info, "display_name", model_name) or model_name
        res = {
            "status": STATUS_AI_READY,
            "configured": True,
            "model": model_name,
            "display_name": display,
            "message": f"Gemini AI verified and reachable ({display})."
        }
    except Exception as e:
        err_msg = str(e)
        err_lower = err_msg.lower()
        code = getattr(e, "code", None) or getattr(e, "status_code", None)

        if code in [400, 401, 403] or any(t in err_lower for t in ["api_key_invalid", "permission_denied", "invalid api key", "unregistered_callers"]):
            res = {
                "status": STATUS_AI_AUTH_FAILED,
                "configured": True,
                "model": model_name,
                "message": "Gemini authentication failed: Invalid API key or permission denied."
            }
        elif code == 404 or any(t in err_lower for t in ["not_found", "model not found", "is not supported"]):
            res = {
                "status": STATUS_AI_MODEL_UNAVAILABLE,
                "configured": True,
                "model": model_name,
                "message": f"Configured model '{model_name}' was not found or is unavailable."
            }
        elif code == 429 or any(t in err_lower for t in ["resource_exhausted", "quota", "rate limit"]):
            res = {
                "status": STATUS_AI_QUOTA_EXCEEDED,
                "configured": True,
                "model": model_name,
                "message": "Gemini quota or rate limit exceeded."
            }
        elif code == 503 or "unavailable" in err_lower:
            res = {
                "status": STATUS_AI_UNAVAILABLE_OFFLINE,
                "configured": True,
                "model": model_name,
                "message": "Gemini service is temporarily unavailable (HTTP 503)."
            }
        elif isinstance(e, (ConnectionError, TimeoutError, OSError)) or any(term in err_lower for term in ["connect", "timeout", "unreachable", "dns", "socket", "network", "gaierror", "resolve", "host"]):
            res = {
                "status": STATUS_AI_UNAVAILABLE_OFFLINE,
                "configured": True,
                "model": model_name,
                "message": "Google Gemini API is unreachable (network or connection failure)."
            }
        else:
            res = {
                "status": STATUS_AI_REQUEST_FAILED,
                "configured": True,
                "model": model_name,
                "message": f"Gemini status check failed: {err_msg[:120]}"
            }

    _STATUS_CACHE["data"] = res
    _STATUS_CACHE["timestamp"] = now
    _STATUS_CACHE["key_hash"] = key_hash
    _STATUS_CACHE["model"] = model_name
    return res


def _strip_canaries(text: str) -> str:
    """Removes any detected canary secrets, IP addresses, or internal absolute paths from a text string."""
    cleaned = text
    for pat in SENSITIVE_PATTERNS:
        cleaned = pat.sub("[REDACTED]", cleaned)
    return cleaned


def sanitize_context_for_gemini(raw_context: Dict[str, Any], audience: Optional[str] = None) -> Dict[str, Any]:
    """
    Strict Privacy Filter:
    Explicitly whitelist only safe public vulnerability metadata.
    Completely excludes source code, passwords, internal IPs, AWS/GCP secrets,
    and absolute filesystem paths.
    """
    pkg_raw = raw_context.get("package_name") or raw_context.get("target_node_id", "")
    # Clean node prefixes if present (pkg:, ext:, etc.)
    pkg_clean = str(pkg_raw).replace("pkg:trans:", "").replace("pkg:", "").replace("ext:", "").strip()
    
    title = _strip_canaries(str(raw_context.get("title", "")))
    pkg = _strip_canaries(pkg_clean)
    ver = _strip_canaries(str(raw_context.get("version") or raw_context.get("installed_version") or "unknown"))
    cve = _strip_canaries(str(raw_context.get("cve_id") or "")) if raw_context.get("cve_id") else None
    sev = str(raw_context.get("severity", "medium")).lower()
    journey = _strip_canaries(str(raw_context.get("journey_name") or raw_context.get("affected_business_journey") or "Core Business Operation"))
    aud = str(audience or raw_context.get("audience", "builder")).lower()

    authoritative = resolve_authoritative_advisory(
        package_name=pkg,
        installed_version=ver,
        cve_id=cve,
        provided_details=raw_context.get("security_details") or raw_context
    )

    sanitized = {
        "finding_id": str(raw_context.get("finding_id", "unknown")),
        "title": title,
        "target_package": pkg,
        "version": ver,
        "cve_id": authoritative.get("cve_id") or cve,
        "severity": authoritative.get("severity") or sev,
        "affected_business_journey": journey,
        "audience": aud,
        "authoritative_details": authoritative
    }

    # Verify that no disallowed keys made it into the sanitized payload
    forbidden_keys = {"source_code", "file_path", "internal_ip", "aws_secret", "env", "password", "token"}
    for k in forbidden_keys:
        if k in sanitized:
            del sanitized[k]

    return sanitized


def get_fallback_explanation(sanitized: Dict[str, Any], error_code: str = STATUS_AI_NOT_CONFIGURED, error_message: str = "") -> Dict[str, Any]:
    """
    Deterministic rule-based explanation when GEMINI_API_KEY is not configured or network fails.
    Preserves local-first analysis and provides actionable status error codes.
    """
    audience = sanitized.get("audience", "builder")
    pkg = sanitized.get("target_package", "dependency")
    ver = sanitized.get("version", "unknown")
    cve = sanitized.get("cve_id") or "Security Advisory"
    sev = sanitized.get("severity", "medium")
    journey = sanitized.get("affected_business_journey", "Core Operations")
    audience = str(sanitized.get("audience", "builder")).lower()

    if audience in ["builder", "developer"]:
        summary = f"Package '{pkg}' (v{ver}) is affected by {cve}. Connected to journey '{journey}'."
        why_it_matters = f"If '{pkg}' is compromised, operations in '{journey}' may be disrupted or manipulated."
        steps = [
            f"Run 'npm update {pkg}' or check your package manager to upgrade to a patched release.",
            "Verify locally that builds and unit tests pass regression checks.",
            "Commit and deploy updated dependencies through your CI/CD pipeline."
        ]
    else:
        summary = f"Security vulnerability {cve} ({sev.upper()}) identified in dependency '{pkg}@{ver}'."
        why_it_matters = f"Propagates downstream blast radius directly to business journey '{journey}', impacting business continuity and audit compliance."
        steps = [
            f"Audit lockfile and enforce minimum patched version for '{pkg}'.",
            f"Review architecture blast radius and isolate dependent endpoints where possible.",
            "Verify compliance standards and validate vendor resilience posture."
        ]

    notice_msg = f"Status: {error_code}"
    if error_message:
        notice_msg += f" — {error_message}"

    auth = sanitized.get("authoritative_details") or resolve_authoritative_advisory(
        sanitized.get("target_package", ""),
        sanitized.get("version", ""),
        sanitized.get("cve_id")
    )
    base_data = {
        "summary": summary,
        "why_it_matters": why_it_matters,
        "technical_impact": f"Supply-chain dependency propagation affecting journey '{journey}' (Severity: {sev.upper()}).",
        "safe_remediation_steps": steps,
        "confidence_score": 0.95
    }
    grounded = validate_and_ground_explanation(base_data, auth, audience)

    return {
        "finding_id": sanitized.get("finding_id"),
        "target_package": pkg,
        "version": ver,
        "audience": audience,
        "summary": grounded["summary"],
        "why_it_matters": grounded["why_it_matters"],
        "technical_impact": grounded["technical_impact"],
        "safe_remediation_steps": grounded["safe_remediation_steps"],
        "confidence_score": grounded["confidence_score"],
        "is_ai_generated": False,
        "is_fallback": True,
        "ai_status": error_code,
        "error_message": error_message,
        "notice": notice_msg,
        "verified_scanner_finding": grounded["verified_scanner_finding"],
        "ai_generated_explanation": grounded["ai_generated_explanation"],
        "ai_generated_inference": grounded["ai_generated_inference"],
        "unverified_information": grounded["unverified_information"],
        "validation_report": grounded["validation_report"]
    }


def _classify_gemini_error(exc: Exception) -> tuple[str, str]:
    """
    Maps Google GenAI and network exceptions to precise user-facing error categories:
    - AI_AUTH_FAILED
    - AI_QUOTA_EXCEEDED
    - AI_MODEL_UNAVAILABLE
    - AI_UNAVAILABLE_OFFLINE
    - AI_REQUEST_FAILED
    """
    msg = str(exc)
    msg_lower = msg.lower()

    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "timeout" in msg_lower or "timed out" in msg_lower:
        return STATUS_AI_UNAVAILABLE_OFFLINE, "Connection to Google Gemini API timed out. Please verify internet connectivity."

    if "connection" in msg_lower or "network" in msg_lower or "unreachable" in msg_lower or "dns" in msg_lower or "name or service not known" in msg_lower:
        return STATUS_AI_UNAVAILABLE_OFFLINE, "Network offline or Google Gemini service unreachable."

    if isinstance(exc, APIError):
        code = getattr(exc, "code", 0)
        if code in [401, 403] or "api key not valid" in msg_lower or "api_key_invalid" in msg_lower or "permission" in msg_lower:
            return STATUS_AI_AUTH_FAILED, "Invalid or unauthorized Google Gemini API key."
        if code == 429 or "quota" in msg_lower or "resource_exhausted" in msg_lower or "rate limit" in msg_lower:
            return STATUS_AI_QUOTA_EXCEEDED, "Gemini API rate limit or quota exceeded. Please retry shortly."
        if code == 404 or ("not found" in msg_lower and "model" in msg_lower):
            return STATUS_AI_MODEL_UNAVAILABLE, f"Configured Gemini model is unavailable or unsupported."
        if code == 503 or "503" in msg or "unavailable" in msg_lower or "overloaded" in msg_lower:
            return STATUS_AI_REQUEST_FAILED, "Google Gemini service temporarily unavailable (503). Server overloaded."
        return STATUS_AI_REQUEST_FAILED, f"Gemini API request failed (HTTP {code}): {msg}"

    if "api key not valid" in msg_lower or "api_key_invalid" in msg_lower or "unauthorized" in msg_lower:
        return STATUS_AI_AUTH_FAILED, "Invalid or unauthorized Google Gemini API key."
    if "429" in msg or "quota" in msg_lower:
        return STATUS_AI_QUOTA_EXCEEDED, "Gemini API quota exceeded."
    if "404" in msg or "model" in msg_lower and "not found" in msg_lower:
        return STATUS_AI_MODEL_UNAVAILABLE, "Gemini model identifier not found."

    return STATUS_AI_REQUEST_FAILED, f"AI analysis error: {msg}"


async def explain_finding(raw_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a structured explanation using the Google Gemini SDK.
    Enforces context sanitization, timeouts, structured JSON responses, and error visibility.
    """
    sanitized = sanitize_context_for_gemini(raw_context)
    api_key = get_gemini_api_key(raw_context.get("api_key"))

    if not api_key:
        logger.info("GEMINI_API_KEY not configured. Returning deterministic local explanation.")
        return get_fallback_explanation(sanitized, STATUS_AI_NOT_CONFIGURED, "GEMINI_API_KEY is not configured in backend/.env")

    model_name = getattr(settings, "GEMINI_MODEL", None) or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

    auth = sanitized.get("authoritative_details") or resolve_authoritative_advisory(
        sanitized["target_package"],
        sanitized["version"],
        sanitized.get("cve_id")
    )
    status = auth.get("verification_status", "VERIFIED_VULNERABLE")
    fixed_ver = auth.get("fixed_version")
    affected_range = auth.get("affected_version_range")
    desc = auth.get("advisory_description") or "Authoritative advisory finding."
    source = auth.get("advisory_source") or "Deterministic Vulnerability Scanner"

    prompt = f"""You are the security and dependency intelligence engine for BlindSpot.
Your explanation MUST be strictly grounded in the authoritative scanner finding below.
Do NOT re-evaluate whether the version is vulnerable or invent new version ranges.

AUTHORITATIVE SOURCE OF TRUTH (Deterministic Scanner):
- Package: {sanitized['target_package']}
- Scanned / Installed Version: {sanitized['version']}
- Advisory / CVE: {sanitized['cve_id'] or 'Known Vulnerability'}
- Verification Status: {status}
- Affected Version Range: {affected_range or 'unverified'}
- Authoritative Fixed Version: {fixed_ver or 'None published'}
- Severity: {sanitized['severity']} (CVSS: {auth.get('cvss_score', 'N/A')})
- Advisory Source: {source}
- Authoritative Advisory Summary: {desc}
- Business Journey: {sanitized['affected_business_journey']}
- Audience Perspective: {sanitized['audience'].upper()}

GROUNDING RULES:
1. If Verification Status is ALREADY_FIXED: Clearly explain that installed version {sanitized['version']} is NOT vulnerable because it meets or exceeds the fixed version ({fixed_ver}). Do not tell the user to upgrade.
2. If Verification Status is VERIFIED_VULNERABLE: Explain the real vulnerability as described in the authoritative summary. Only recommend upgrading to the authoritative fixed version ({fixed_ver}).
3. If Verification Status is MISSING_FIX_INFORMATION: Explicitly state that verification is required before taking action because no fixed release is published.
4. If Verification Status is UNVERIFIED_ADVISORY: Explicitly state that the advisory is unconfirmed in authoritative databases and needs verification.
5. Do not invent any CVE numbers, exploit paths, or unverified upgrade versions.

Respond strictly in valid JSON without markdown code fences (```):
{{
  "summary": "1-2 sentence overview strictly grounded in the authoritative findings",
  "why_it_matters": "Business/runtime continuity impact grounded in the finding",
  "technical_impact": "Technical impact grounded strictly in the authoritative description",
  "safe_remediation_steps": ["step 1", "step 2", "step 3"]
}}"""

    # Bounded exponential backoff for transient errors (e.g. 503, 429, timeouts)
    max_retries = 3
    base_backoff = 1.0
    max_backoff = 8.0
    last_error_status = STATUS_AI_REQUEST_FAILED
    last_error_message = ""

    for attempt in range(max_retries):
        try:
            client = Client(api_key=api_key)
            # Use asyncio.wait_for with a 15-second timeout
            call_coro = client.aio.models.generate_content(
                model=model_name,
                contents=prompt
            )
            response = await asyncio.wait_for(call_coro, timeout=15.0)

            if not response or not response.text:
                raise ValueError("Empty response received from Gemini API")

            raw_text = response.text.strip()
            # Strip markdown code fence if returned
            if raw_text.startswith("```"):
                lines = raw_text.splitlines()
                raw_text = "\n".join([l for l in lines if not l.startswith("```")])

            data = json.loads(raw_text)

            # Post-generation authoritative validation layer
            grounded = validate_and_ground_explanation(data, auth, sanitized["audience"])

            update_gemini_status_cache(STATUS_AI_READY, f"Gemini AI verified and reachable ({model_name}).", model_name)
            return {
                "finding_id": sanitized.get("finding_id"),
                "target_package": sanitized.get("target_package"),
                "version": sanitized.get("version"),
                "audience": sanitized.get("audience"),
                "summary": grounded["summary"],
                "why_it_matters": grounded["why_it_matters"],
                "technical_impact": grounded["technical_impact"],
                "safe_remediation_steps": grounded["safe_remediation_steps"],
                "confidence_score": grounded["confidence_score"],
                "is_ai_generated": True,
                "is_fallback": False,
                "ai_status": STATUS_AI_READY,
                "model_used": model_name,
                "notice": f"Live Analysis Powered by Google Gemini ({model_name}) — Grounded in Authoritative Advisory ({source}).",
                "verified_scanner_finding": grounded["verified_scanner_finding"],
                "ai_generated_explanation": grounded["ai_generated_explanation"],
                "ai_generated_inference": grounded["ai_generated_inference"],
                "unverified_information": grounded["unverified_information"],
                "validation_report": grounded["validation_report"]
            }

        except (APIError, ClientError, ServerError, asyncio.TimeoutError, TimeoutError, ValueError, Exception) as exc:
            err_code, err_msg = _classify_gemini_error(exc)
            last_error_status = err_code
            last_error_message = err_msg
            logger.warning(f"Gemini call attempt {attempt + 1}/{max_retries} failed ({err_code}): {err_msg}")

            # Do not retry auth errors or model not found errors
            if err_code in [STATUS_AI_AUTH_FAILED, STATUS_AI_MODEL_UNAVAILABLE]:
                break

            if attempt < max_retries - 1:
                # Bounded exponential backoff: attempt 0 -> 1s, attempt 1 -> 2s (capped at max_backoff)
                backoff_delay = min(max_backoff, base_backoff * (2 ** attempt))
                logger.info(f"Retrying Gemini call in {backoff_delay:.1f}s (bounded exponential backoff)...")
                await asyncio.sleep(backoff_delay)

    # Return structured error fallback with exact underlying reason
    return get_fallback_explanation(sanitized, last_error_status, last_error_message)


async def enrich_vendor_profile(vendor_domain: str) -> Dict[str, Any]:
    """
    Retrieves publicly disclosed sub-processors for third-party vendors.
    Maintains offline curated vendor database as primary local-first source.
    """
    clean_domain = vendor_domain.lower().replace("https://", "").replace("http://", "").strip().split("/")[0]

    CURATED_VENDOR_DB = {
        "stripe.com": {
            "vendor": "Stripe, Inc.",
            "domain": "stripe.com",
            "disclosed_subprocessors": ["Amazon Web Services (AWS US-East-1)", "Cloudflare Edge", "Datadog Telemetry"],
            "sources": ["https://stripe.com/privacy/subprocessors", "SEC 10-K Filings"],
            "passport_available": True
        },
        "auth0.com": {
            "vendor": "Auth0 (Okta)",
            "domain": "auth0.com",
            "disclosed_subprocessors": ["Amazon Web Services (AWS)", "Fastly CDN", "MongoDB Atlas"],
            "sources": ["https://auth0.com/security/subprocessors"],
            "passport_available": True
        },
        "twilio.com": {
            "vendor": "Twilio Inc.",
            "domain": "twilio.com",
            "disclosed_subprocessors": ["Amazon Web Services (AWS)", "Google Cloud Platform", "Cloudflare"],
            "sources": ["https://www.twilio.com/legal/sub-processors"],
            "passport_available": True
        }
    }

    if clean_domain in CURATED_VENDOR_DB:
        profile = dict(CURATED_VENDOR_DB[clean_domain])
        profile["is_curated"] = True
        return profile

    api_key = get_gemini_api_key()
    if api_key:
        try:
            client = Client(api_key=api_key)
            prompt = f"List the publicly known cloud sub-processors and CDNs used by {clean_domain} in JSON format: {{\"vendor\": \"{clean_domain}\", \"disclosed_subprocessors\": [\"cloud1\", \"cdn1\"], \"sources\": [\"url\"]}}"
            res = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=DEFAULT_GEMINI_MODEL,
                    contents=prompt
                ),
                timeout=10.0
            )
            if res and res.text:
                raw_text = res.text.strip().replace("```json", "").replace("```", "").strip()
                data = json.loads(raw_text)
                data["is_curated"] = False
                return data
        except Exception as exc:
            logger.warning(f"Gemini vendor profile enrichment failed for {clean_domain}: {exc}")

    return {
        "vendor": clean_domain,
        "domain": clean_domain,
        "disclosed_subprocessors": ["Public Cloud Infrastructure", "Global Content Delivery Network"],
        "sources": [f"https://{clean_domain}/privacy"],
        "is_curated": False
    }
