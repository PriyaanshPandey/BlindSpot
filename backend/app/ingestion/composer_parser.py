"""
Composer Dependency Parser [Role A]:
Parses composer.json and composer.lock files for PHP dependencies.
Identifies direct, dev, and transitive dependencies, preserving resolved versions
and package relationships while handling malformed or incomplete files gracefully.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from packaging.version import Version, InvalidVersion

logger = logging.getLogger("hdx.ingestion.composer")


@dataclass
class ComposerPackage:
    """Represents a resolved PHP package from composer.lock."""
    name: str
    version: str
    is_direct: bool = False
    is_dev: bool = False
    description: Optional[str] = None
    source_url: Optional[str] = None
    declared_dependencies: Dict[str, str] = field(default_factory=dict)
    resolved_dependency_keys: List[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"pkg:composer/{self.name}@{self.version}"


@dataclass
class ComposerLockfileResult:
    """Structured extraction of Composer dependencies and consistency diagnostics."""
    project_name: str
    packages: Dict[str, ComposerPackage] = field(default_factory=dict)
    direct_packages: List[ComposerPackage] = field(default_factory=list)
    dev_packages: List[ComposerPackage] = field(default_factory=list)
    transitive_packages: List[ComposerPackage] = field(default_factory=list)
    dependency_edges: List[Dict[str, str]] = field(default_factory=list)
    platform_requirements: Dict[str, str] = field(default_factory=dict)
    inconsistencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def is_consistent(self) -> bool:
        return len(self.inconsistencies) == 0


def _is_platform_requirement(pkg_name: str) -> bool:
    """Detects PHP runtime or extension constraints (e.g. php, ext-json, lib-*)."""
    clean = pkg_name.lower()
    return clean == "php" or clean.startswith("ext-") or clean.startswith("lib-")


def parse_composer_json(file_path: str) -> Dict[str, Any]:
    """
    Parses composer.json to extract declared requirements.
    Separates actual library dependencies from PHP platform/extension requirements.
    """
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        req = data.get("require", {}) or {}
        req_dev = data.get("require-dev", {}) or {}

        package_deps = {k: v for k, v in req.items() if not _is_platform_requirement(k)}
        platform_reqs = {k: v for k, v in req.items() if _is_platform_requirement(k)}
        dev_package_deps = {k: v for k, v in req_dev.items() if not _is_platform_requirement(k)}

        return {
            "name": data.get("name", "unknown"),
            "version": data.get("version"),
            "description": data.get("description", ""),
            "dependencies": package_deps,
            "devDependencies": dev_package_deps,
            "platformRequirements": platform_reqs
        }
    except Exception as e:
        logger.warning(f"Failed to parse composer.json at {file_path}: {e}")
        return {}


def _parse_semver(ver_str: str) -> Version:
    """Parses a semver string, ignoring build metadata per SemVer 2.0.0 precedence."""
    raw = ver_str.lstrip("v").strip()
    v = Version(raw)
    if v.local is not None:
        return Version(v.public)
    return v


def check_composer_version_satisfies(version_str: str, constraint: str) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether a resolved version satisfies a declared Composer range constraint.
    Accurately reflects Composer constraint semantics without assuming NPM rules.
    """
    if not constraint or not version_str:
        return False, "unsupported: empty constraint or version string"

    clean_ver = version_str.lstrip("v").strip()
    clean_constraint = constraint.strip()

    if clean_constraint in ("*", ""):
        return True, None

    # Handle union with || or |
    if "||" in clean_constraint or "|" in clean_constraint:
        delims = "||" if "||" in clean_constraint else "|"
        or_clauses = [c.strip() for c in clean_constraint.split(delims) if c.strip()]
        for or_c in or_clauses:
            ok, _ = check_composer_version_satisfies(version_str, or_c)
            if ok:
                return True, None
        return False, f"drift: resolved version '{version_str}' does not satisfy Composer union range '{constraint}'"

    # Handle Caret (^)
    if clean_constraint.startswith("^"):
        target_str = clean_constraint[1:].lstrip("v").strip()
        try:
            target_v = _parse_semver(target_str)
            ver = _parse_semver(clean_ver)
        except (InvalidVersion, TypeError):
            return False, f"unsupported: invalid version in constraint '{constraint}'"

        major, minor, micro = target_v.major, target_v.minor, target_v.micro
        if major > 0:
            upper_v = Version(f"{major + 1}.0.0")
        elif minor > 0:
            upper_v = Version(f"0.{minor + 1}.0")
        else:
            upper_v = Version(f"0.0.{micro + 1}")

        if ver >= target_v and ver < upper_v:
            return True, None
        return False, f"drift: resolved version '{version_str}' does not satisfy Composer caret range '{constraint}' (expected >={target_v}, <{upper_v})"

    # Handle Tilde (~)
    if clean_constraint.startswith("~"):
        target_str = clean_constraint[1:].lstrip("v").strip()
        try:
            target_v = _parse_semver(target_str)
            ver = _parse_semver(clean_ver)
        except (InvalidVersion, TypeError):
            return False, f"unsupported: invalid version in constraint '{constraint}'"

        # In Composer: ~1.2 means >=1.2 <2.0; ~1.2.3 means >=1.2.3 <1.3.0
        parts = target_str.split(".")
        if len(parts) <= 2:
            upper_v = Version(f"{target_v.major + 1}.0.0")
        else:
            upper_v = Version(f"{target_v.major}.{target_v.minor + 1}.0")

        if ver >= target_v and ver < upper_v:
            return True, None
        return False, f"drift: resolved version '{version_str}' does not satisfy Composer tilde range '{constraint}'"

    # Handle wildcards like 7.8.*
    if ".*" in clean_constraint:
        base = clean_constraint.replace(".*", "").lstrip("v").strip()
        try:
            ver = _parse_semver(clean_ver)
            parts = base.split(".")
            if len(parts) == 1:
                major = int(parts[0])
                if Version(f"{major}.0.0") <= ver < Version(f"{major + 1}.0.0"):
                    return True, None
            elif len(parts) == 2:
                major, minor = int(parts[0]), int(parts[1])
                if Version(f"{major}.{minor}.0") <= ver < Version(f"{major}.{minor + 1}.0"):
                    return True, None
        except Exception:
            return False, f"unsupported: wildcard range '{constraint}'"
        return False, f"drift: resolved version '{version_str}' does not satisfy Composer wildcard range '{constraint}'"

    # Parse space or comma separated comparators
    normalized_clause = clean_constraint.replace(",", " ")
    clauses = normalized_clause.split()
    try:
        ver = _parse_semver(clean_ver)
    except (InvalidVersion, TypeError):
        return False, f"unsupported: resolved version '{version_str}' cannot be parsed as semver"

    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue
        try:
            if clause.startswith("<="):
                if not (ver <= _parse_semver(clause[2:])):
                    return False, f"drift: '{version_str}' is not <= '{clause[2:]}'"
            elif clause.startswith("<"):
                if not (ver < _parse_semver(clause[1:])):
                    return False, f"drift: '{version_str}' is not < '{clause[1:]}'"
            elif clause.startswith(">="):
                if not (ver >= _parse_semver(clause[2:])):
                    return False, f"drift: '{version_str}' is not >= '{clause[2:]}'"
            elif clause.startswith(">"):
                if not (ver > _parse_semver(clause[1:])):
                    return False, f"drift: '{version_str}' is not > '{clause[1:]}'"
            elif clause.startswith("==") or clause.startswith("="):
                target = clause.lstrip("=").lstrip("v").strip()
                if not (ver == _parse_semver(target)):
                    return False, f"drift: '{version_str}' is not == '{target}'"
            else:
                target = clause.lstrip("v").strip()
                if not (ver == _parse_semver(target)):
                    return False, f"drift: '{version_str}' does not equal exact declared version '{target}'"
        except (InvalidVersion, TypeError):
            return False, f"unsupported: invalid version format in clause '{clause}'"

    return True, None


def parse_composer_lock(
    lock_file_path: str,
    composer_json_path: Optional[str] = None,
    root_app_id: Optional[str] = None
) -> ComposerLockfileResult:
    """
    Authoritative parser for composer.lock.
    Cross-references with composer.json to identify direct vs transitive dependencies.
    """
    if not os.path.exists(lock_file_path):
        raise FileNotFoundError(f"composer.lock not found: {lock_file_path}")

    try:
        with open(lock_file_path, "r", encoding="utf-8") as f:
            lock_data = json.load(f)
    except Exception as e:
        logger.error(f"Malformed composer.lock at {lock_file_path}: {e}")
        return ComposerLockfileResult(
            project_name="unknown",
            inconsistencies=[f"Malformed composer.lock: {e}"]
        )

    project_name = "unknown"
    declared_direct: Set[str] = set()
    declared_dev: Set[str] = set()
    platform_reqs: Dict[str, str] = {}

    if composer_json_path and os.path.exists(composer_json_path):
        manifest = parse_composer_json(composer_json_path)
        project_name = manifest.get("name", "unknown")
        declared_direct = set(manifest.get("dependencies", {}).keys())
        declared_dev = set(manifest.get("devDependencies", {}).keys())
        platform_reqs = manifest.get("platformRequirements", {})

    packages_map: Dict[str, ComposerPackage] = {}
    inconsistencies: List[str] = []
    warnings: List[str] = []

    def _process_package_entry(entry: Dict[str, Any], is_dev: bool):
        name = entry.get("name")
        if not name:
            return
        version = entry.get("version", "").lstrip("v")
        if not version:
            inconsistencies.append(f"Composer package '{name}' is missing version in lockfile")
            return

        is_direct = (name in declared_direct) or (name in declared_dev)
        raw_require = entry.get("require", {}) or {}
        # Filter out platform requirements in dependencies
        sub_deps = {k: v for k, v in raw_require.items() if not _is_platform_requirement(k)}

        source_info = entry.get("source", {})
        source_url = source_info.get("url") if isinstance(source_info, dict) else None

        pkg = ComposerPackage(
            name=name,
            version=version,
            is_direct=is_direct,
            is_dev=is_dev or (name in declared_dev),
            description=entry.get("description"),
            source_url=source_url,
            declared_dependencies=sub_deps
        )
        packages_map[name] = pkg

    # 1. Production packages
    for entry in lock_data.get("packages", []):
        if isinstance(entry, dict):
            _process_package_entry(entry, is_dev=False)

    # 2. Dev packages
    for entry in lock_data.get("packages-dev", []):
        if isinstance(entry, dict):
            _process_package_entry(entry, is_dev=True)

    # Detect packages declared in composer.json but missing from composer.lock, and check version drift
    declared_deps_map = manifest.get("dependencies", {}) if composer_json_path else {}
    declared_dev_map = manifest.get("devDependencies", {}) if composer_json_path else {}

    for direct_name in declared_direct:
        if direct_name not in packages_map:
            inconsistencies.append(
                f"Declared Composer production package '{direct_name}' is missing from composer.lock"
            )
        else:
            req_constraint = declared_deps_map.get(direct_name)
            if req_constraint:
                ok, reason = check_composer_version_satisfies(packages_map[direct_name].version, req_constraint)
                if not ok:
                    msg = f"Declared Composer package '{direct_name}' ({req_constraint}) lockfile mismatch: {reason}"
                    inconsistencies.append(msg)
                    warnings.append(msg)

    for dev_name in declared_dev:
        if dev_name not in packages_map:
            inconsistencies.append(
                f"Declared Composer dev package '{dev_name}' is missing from composer.lock"
            )
        else:
            req_constraint = declared_dev_map.get(dev_name)
            if req_constraint:
                ok, reason = check_composer_version_satisfies(packages_map[dev_name].version, req_constraint)
                if not ok:
                    msg = f"Declared Composer dev package '{dev_name}' ({req_constraint}) lockfile mismatch: {reason}"
                    inconsistencies.append(msg)
                    warnings.append(msg)

    # Build dependency edges: Consumer -> Dependency
    dependency_edges: List[Dict[str, str]] = []

    # Direct edges from application root
    root_source = root_app_id if root_app_id else f"app:{project_name}"
    for pkg in packages_map.values():
        if pkg.is_direct:
            dependency_edges.append({
                "source": root_source,
                "target": pkg.id,
                "relation": "depends_on",
                "consumer_name": project_name,
                "dependency_name": pkg.name,
                "dependency_version": pkg.version
            })

    # Transitive edges between packages
    for parent_pkg in packages_map.values():
        for req_name, req_ver in parent_pkg.declared_dependencies.items():
            child_pkg = packages_map.get(req_name)
            if child_pkg:
                parent_pkg.resolved_dependency_keys.append(child_pkg.id)
                dependency_edges.append({
                    "source": parent_pkg.id,
                    "target": child_pkg.id,
                    "relation": "transitive_dependency",
                    "consumer_name": parent_pkg.name,
                    "dependency_name": child_pkg.name,
                    "dependency_version": child_pkg.version
                })
            else:
                warnings.append(
                    f"Composer package '{parent_pkg.name}' requires '{req_name}' ({req_ver}), but it was not found in composer.lock"
                )

    direct_list = [p for p in packages_map.values() if p.is_direct and not p.is_dev]
    dev_list = [p for p in packages_map.values() if p.is_dev]
    transitive_list = [p for p in packages_map.values() if not p.is_direct]

    return ComposerLockfileResult(
        project_name=project_name,
        packages=packages_map,
        direct_packages=direct_list,
        dev_packages=dev_list,
        transitive_packages=transitive_list,
        dependency_edges=dependency_edges,
        platform_requirements=platform_reqs,
        inconsistencies=inconsistencies,
        warnings=warnings
    )
