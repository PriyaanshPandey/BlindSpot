"""
Safe Package Code Retrieval & Artifact Verification Engine:
1. Priority: Local node_modules inspection -> verified lockfile download -> safe extraction.
2. Integrity validation (SHA-512, SHA-1).
3. Safe extraction with strict path traversal, symlink, and depth protection.
4. SSRF protection: strict HTTPS, approved public registries, IP validation against loopback/RFC1918.
5. Caching & size/time bounds.
"""
import os
import tarfile
import hashlib
import base64
import logging
import ipaddress
import urllib.parse
from typing import Optional, Tuple, Dict, Any, List
import httpx

from app.intelligence.models import PackageInstance, RetrievalStatus

logger = logging.getLogger("hdx.intelligence.retrieval")

# Safety Bounds
MAX_TARBALL_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB
MAX_EXTRACTED_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_EXTRACTED_FILES = 5000
MAX_EXTRACTION_DEPTH = 12
DEFAULT_CACHE_DIR = os.path.abspath("./.package_cache")

ALLOWED_REGISTRY_HOSTS = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "npm.pkg.github.com",
    "pypi.org",
    "files.pythonhosted.org"
}

class SecuritySSRFError(Exception):
    pass

class IntegrityMismatchError(Exception):
    pass

class UnsafeArchiveError(Exception):
    pass

def validate_remote_url(url: str) -> str:
    """Strictly validates target URL to avoid SSRF."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise SecuritySSRFError(f"Rejected insecure scheme: {parsed.scheme}. Only HTTPS allowed.")
    
    host = parsed.hostname
    if not host:
        raise SecuritySSRFError("Invalid URL: missing hostname.")

    # Check against allowed registry domains
    if host.lower() not in ALLOWED_REGISTRY_HOSTS:
        # Check if IP address directly
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise SecuritySSRFError(f"Rejected private/loopback IP address {host}")
        except ValueError:
            pass # domain name
        if not (host.endswith(".npmjs.org") or host.endswith(".pythonhosted.org")):
            raise SecuritySSRFError(f"Host '{host}' is not in approved registry hosts list.")

    return url

def verify_checksum(data: bytes, expected_integrity: str) -> bool:
    """Verifies subresource integrity format, e.g. sha512-... or sha1-..."""
    if not expected_integrity:
        return True
    
    parts = expected_integrity.strip().split("-", 1)
    if len(parts) != 2:
        return False
    
    algo, expected_b64 = parts[0].lower(), parts[1]
    
    if algo == "sha512":
        digest = hashlib.sha512(data).digest()
    elif algo == "sha1":
        digest = hashlib.sha1(data).digest()
    elif algo == "sha256":
        digest = hashlib.sha256(data).digest()
    else:
        logger.warning(f"Unsupported integrity algorithm: {algo}")
        return False

    calculated_b64 = base64.b64encode(digest).decode("ascii")
    return calculated_b64 == expected_b64

def is_safe_tar_member(member: tarfile.TarInfo, target_dir: str) -> bool:
    """Enforces no path traversal, device files, or symlink escapes."""
    target_dir = os.path.abspath(target_dir)
    # Check for absolute paths
    if member.name.startswith(("/", "\\")) or ":" in member.name:
        return False
    
    # Resolve extracted path
    destination_path = os.path.abspath(os.path.join(target_dir, member.name))
    if not (destination_path == target_dir or destination_path.startswith(target_dir + os.sep)):
        return False
    
    # Check file type: only normal files, directories
    if not (member.isreg() or member.isdir()):
        return False
    
    # Depth check
    rel = os.path.relpath(destination_path, target_dir)
    if len(rel.split(os.sep)) > MAX_EXTRACTION_DEPTH:
        return False

    return True

def safe_extract_tar(tar_path: str, destination_dir: str) -> Tuple[bool, Optional[str]]:
    """Safely extracts a verified tarball with strict bounds and validation."""
    os.makedirs(destination_dir, exist_ok=True)
    total_size = 0
    file_count = 0

    try:
        with tarfile.open(tar_path, "r:*") as tar:
            members = tar.getmembers()
            for member in members:
                file_count += 1
                if file_count > MAX_EXTRACTED_FILES:
                    return False, f"Archive exceeds maximum file count limit ({MAX_EXTRACTED_FILES})"
                
                total_size += member.size
                if total_size > MAX_EXTRACTED_SIZE_BYTES:
                    return False, f"Archive extracted size exceeds maximum allowed limit ({MAX_EXTRACTED_SIZE_BYTES} bytes)"
                
                if not is_safe_tar_member(member, destination_dir):
                    return False, f"Unsafe archive entry detected: '{member.name}'"

            # Safe to extract
            tar.extractall(path=destination_dir)
        return True, None
    except Exception as e:
        return False, str(e)

class PackageArtifactRetriever:
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = os.path.abspath(cache_dir or DEFAULT_CACHE_DIR)
        os.makedirs(self.cache_dir, exist_ok=True)

    def retrieve_package(
        self,
        package: PackageInstance,
        project_root: str,
        allow_network: bool = True
    ) -> PackageInstance:
        """
        Retrieves exact published package code based on the 5-step priority order:
        1. Local node_modules installation check.
        2. Remote download if lockfile URL exists.
        3. Integrity hash validation.
        4. Safe isolated extraction.
        5. Ready for source scanning.
        """
        # Step 1: Check existing local node_modules in project
        if package.install_path:
            local_installed = os.path.join(project_root, package.install_path)
            if os.path.isdir(local_installed):
                package.has_source_retrieved = True
                package.retrieval_status = RetrievalStatus.LOCAL_NODE_MODULES
                package.extracted_source_path = local_installed
                return package

        # If no resolved URL, cannot download
        resolved_url = package.resolved_url
        if not resolved_url:
            package.has_source_retrieved = False
            package.retrieval_status = RetrievalStatus.UNSUPPORTED_SOURCE
            return package

        # Validate URL for SSRF
        try:
            valid_url = validate_remote_url(resolved_url)
        except SecuritySSRFError as e:
            logger.warning(f"SSRF check rejected URL for {package.instance_id}: {e}")
            package.has_source_retrieved = False
            package.retrieval_status = RetrievalStatus.REJECTED_SSRF
            package.metadata["retrieval_error"] = str(e)
            return package

        # Determine cache filenames based on package identity
        cache_slug = hashlib.sha256(package.instance_id.encode("utf-8")).hexdigest()[:16]
        tarball_cache_path = os.path.join(self.cache_dir, f"{cache_slug}.tgz")
        extracted_cache_dir = os.path.join(self.cache_dir, f"{cache_slug}_src")

        # Check if already cached and extracted
        if os.path.isdir(extracted_cache_dir):
            package.has_source_retrieved = True
            package.retrieval_status = RetrievalStatus.REMOTE_VERIFIED
            package.extracted_source_path = extracted_cache_dir
            return package

        if not allow_network:
            package.has_source_retrieved = False
            package.retrieval_status = RetrievalStatus.UNPROCESSED
            return package

        # Step 2: Download artifact
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                resp = client.get(valid_url)
                if resp.status_code != 200:
                    package.has_source_retrieved = False
                    package.retrieval_status = RetrievalStatus.DOWNLOAD_FAILED
                    package.metadata["http_status"] = resp.status_code
                    return package
                
                content = resp.content
                if len(content) > MAX_TARBALL_SIZE_BYTES:
                    package.has_source_retrieved = False
                    package.retrieval_status = RetrievalStatus.DOWNLOAD_FAILED
                    package.metadata["retrieval_error"] = "Package tarball exceeds size limit"
                    return package

            # Step 3: Verify Integrity Hash
            if package.integrity:
                if not verify_checksum(content, package.integrity):
                    logger.error(f"Integrity mismatch for {package.instance_id}")
                    package.has_source_retrieved = False
                    package.retrieval_status = RetrievalStatus.INTEGRITY_MISMATCH
                    package.metadata["retrieval_error"] = f"Integrity check failed against {package.integrity}"
                    return package

            # Write tarball to cache
            with open(tarball_cache_path, "wb") as f:
                f.write(content)

            # Step 4: Extract safely
            success, err = safe_extract_tar(tarball_cache_path, extracted_cache_dir)
            if not success:
                package.has_source_retrieved = False
                package.retrieval_status = RetrievalStatus.EXTRACT_ERROR
                package.metadata["retrieval_error"] = err
                return package

            package.has_source_retrieved = True
            package.retrieval_status = RetrievalStatus.REMOTE_VERIFIED
            # Often npm tarball extracts into "package/" subdirectory
            inner_pkg = os.path.join(extracted_cache_dir, "package")
            package.extracted_source_path = inner_pkg if os.path.isdir(inner_pkg) else extracted_cache_dir
            return package

        except Exception as e:
            logger.error(f"Failed to retrieve remote package {package.instance_id}: {e}")
            package.has_source_retrieved = False
            package.retrieval_status = RetrievalStatus.DOWNLOAD_FAILED
            package.metadata["retrieval_error"] = str(e)
            return package

