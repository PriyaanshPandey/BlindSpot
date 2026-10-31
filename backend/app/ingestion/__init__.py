"""
HDX Ingestion Subsystem [Role A]:
Responsible for parsing declared dependencies (NPM, Composer manifests and lockfiles),
extracting project archives safely, and normalizing observed runtime telemetry.
Exports authoritative discovery interfaces consumed by Role B (Graph Engine).
"""

from app.ingestion.npm_parser import (
    parse_package_json,
    parse_package_json_detailed,
    parse_package_lock_json,
    NpmPackage,
    NpmLockfileResult
)

from app.ingestion.composer_parser import (
    parse_composer_json,
    parse_composer_lock,
    ComposerPackage,
    ComposerLockfileResult
)

from app.ingestion.zip_extractor import (
    SafeZipExtractor,
    SafeZipLimits,
    SafeZipError,
    extract_project_zip,
    ExtractionResult
)

from app.ingestion.trace_normalizer import (
    parse_runtime_traces,
    normalize_runtime_traces,
    ObservedSpan,
    ObservedDependencyGroup,
    TraceNormalizationResult
)

from app.ingestion.discovery_result import (
    DiscoveryResult,
    discover_project
)

__all__ = [
    "parse_package_json",
    "parse_package_json_detailed",
    "parse_package_lock_json",
    "NpmPackage",
    "NpmLockfileResult",
    "parse_composer_json",
    "parse_composer_lock",
    "ComposerPackage",
    "ComposerLockfileResult",
    "SafeZipExtractor",
    "SafeZipLimits",
    "SafeZipError",
    "extract_project_zip",
    "ExtractionResult",
    "parse_runtime_traces",
    "normalize_runtime_traces",
    "ObservedSpan",
    "ObservedDependencyGroup",
    "TraceNormalizationResult",
    "DiscoveryResult",
    "discover_project"
]
