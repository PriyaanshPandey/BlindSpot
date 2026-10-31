"""
NPM Dependency Parser [Role A]:
Authoritative parsing for package.json manifests and package-lock.json (lockfileVersion 2 and 3).
Resolves direct, dev, and transitive dependencies, preserving actual resolved versions,
exact dependency paths, scoped packages, and multiple nested versions.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from packaging.version import Version, InvalidVersion

logger = logging.getLogger("hdx.ingestion.npm")


@dataclass
class NpmPackage:
    """Represents an installed/resolved NPM package from package-lock.json."""
    name: str
    version: str
    path: str
    is_direct: bool = False
    is_dev: bool = False
    resolved: Optional[str] = None
    integrity: Optional[str] = None
    declared_dependencies: Dict[str, str] = field(default_factory=dict)
    resolved_dependency_keys: List[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Unique identifier incorporating name, version, and location path."""
        return f"pkg:npm/{self.name}@{self.version}#{self.path}"


@dataclass
class NpmLockfileResult:
    """Structured extraction of NPM dependency tree and consistency diagnostics."""
    project_name: str
    lockfile_version: int
    packages: Dict[str, NpmPackage] = field(default_factory=dict)
    direct_packages: List[NpmPackage] = field(default_factory=list)
    dev_packages: List[NpmPackage] = field(default_factory=list)
    transitive_packages: List[NpmPackage] = field(default_factory=list)
    dependency_edges: List[Dict[str, str]] = field(default_factory=list)
    inconsistencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def is_consistent(self) -> bool:
        return len(self.inconsistencies) == 0


def parse_package_json(file_path: str) -> Dict[str, Any]:
    """
    Public backward-compatible parser for package.json.
    Returns: {"name": str, "dependencies": combined_dict}
    """
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        return {"name": data.get("name", "unknown"), "dependencies": deps}
    except Exception as e:
        logger.warning(f"Failed to parse package.json at {file_path}: {e}")
        return {}


def parse_package_json_detailed(file_path: str) -> Dict[str, Any]:
    """Extracts segregated production, dev, and peer dependencies with metadata."""
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "name": data.get("name", "unknown"),
        "version": data.get("version"),
        "dependencies": data.get("dependencies", {}) or {},
        "devDependencies": data.get("devDependencies", {}) or {},
        "peerDependencies": data.get("peerDependencies", {}) or {},
        "optionalDependencies": data.get("optionalDependencies", {}) or {},
    }


def _parse_semver(ver_str: str) -> Version:
    """Parses a semver string, ignoring build metadata per SemVer 2.0.0 precedence."""
    raw = ver_str.lstrip("v").strip()
    v = Version(raw)
    if v.local is not None:
        return Version(v.public)
    return v


def _expand_partial_version(text: str) -> Optional[Tuple[Version, Optional[Version]]]:
    """
    Expands a partial or wildcard version string into (lower_bound_inclusive, upper_bound_exclusive).
    Returns (lower, upper) where upper may be None for unbounded wildcards (*).
    Returns None if text is not a partial or wildcard version (e.g., full 3-segment version).
    """
    clean = text.lstrip("v").strip()
    if clean in ("*", "x", "X"):
        return Version("0.0.0"), None

    if "-" in clean or "+" in clean:
        return None

    parts = clean.split(".")
    if len(parts) == 1:
        if parts[0].isdigit():
            m = int(parts[0])
            return Version(f"{m}.0.0"), Version(f"{m + 1}.0.0")
        if parts[0] in ("*", "x", "X"):
            return Version("0.0.0"), None
    elif len(parts) == 2:
        if parts[0].isdigit():
            m = int(parts[0])
            if parts[1].isdigit():
                n = int(parts[1])
                return Version(f"{m}.{n}.0"), Version(f"{m}.{n + 1}.0")
            if parts[1] in ("*", "x", "X"):
                return Version(f"{m}.0.0"), Version(f"{m + 1}.0.0")
    elif len(parts) == 3:
        if parts[0].isdigit() and parts[1].isdigit():
            m, n = int(parts[0]), int(parts[1])
            if parts[2] in ("*", "x", "X"):
                return Version(f"{m}.{n}.0"), Version(f"{m}.{n + 1}.0")
    return None


def check_npm_version_satisfies(version_str: str, constraint: str) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether a resolved version satisfies a declared NPM range constraint.
    Supports: logical OR (||), ^, ~, partial versions (1, 1.2), comparators (>=, <=, >, <, ==),
    hyphen ranges, and wildcards (*, x).
    Returns (True, None) if satisfied.
    Returns (False, "drift: ...") if version drift is detected.
    Returns (False, "unsupported: ...") if constraint format is unsupported.
    """
    if not constraint or not version_str:
        return False, "unsupported: empty constraint or version string"

    clean_ver = version_str.lstrip("v").strip()
    clean_constraint = constraint.strip()

    try:
        ver = _parse_semver(clean_ver)
    except (InvalidVersion, TypeError):
        return False, f"unsupported: resolved version '{version_str}' cannot be parsed as semver"

    # 1. Logical OR (||) must be processed BEFORE individual caret, tilde, wildcard or comparators
    if "||" in clean_constraint:
        alternatives = [c.strip() for c in clean_constraint.split("||")]
        if any(not alt for alt in alternatives):
            return False, f"unsupported: invalid logical OR expression '{constraint}'"

        any_satisfied = False
        unsupported_reason: Optional[str] = None

        for alt in alternatives:
            ok, reason = check_npm_version_satisfies(version_str, alt)
            if ok:
                any_satisfied = True
            elif reason and reason.startswith("unsupported:"):
                if unsupported_reason is None:
                    unsupported_reason = reason

        # Unsupported expressions return an explicit warning rather than being silently accepted
        if unsupported_reason:
            return False, unsupported_reason

        if any_satisfied:
            return True, None
        return False, f"drift: resolved version '{version_str}' does not satisfy union range '{constraint}'"

    # 2. Wildcards (*, x, X, empty)
    if clean_constraint in ("*", "", "x", "X"):
        if ver.is_prerelease:
            return False, f"drift: prerelease version '{version_str}' does not satisfy wildcard range '{constraint}'"
        return True, None

    # 3. Detect unsupported expressions: URLs, file paths, npm aliases, dist-tags
    unsupported_prefixes = ("http:", "https:", "git:", "git+", "file:", "npm:", "portal:")
    if any(clean_constraint.startswith(prefix) for prefix in unsupported_prefixes):
        return False, f"unsupported: URL or local path dependency '{constraint}'"
    if clean_constraint in ("latest", "next", "beta", "alpha", "canary", "dev"):
        return False, f"unsupported: dist-tag constraint '{constraint}'"

    # 4. Hyphen range: "1.2.3 - 2.3.4" -> ">=1.2.3 <=2.3.4"
    if " - " in clean_constraint:
        parts = clean_constraint.split(" - ")
        if len(parts) == 2:
            left, right = parts[0].strip(), parts[1].strip()
            left_partial = _expand_partial_version(left)
            right_partial = _expand_partial_version(right)
            left_str = str(left_partial[0]) if left_partial else left
            if right_partial and right_partial[1] is not None:
                clean_constraint = f">={left_str} <{right_partial[1]}"
            else:
                clean_constraint = f">={left_str} <={right}"

    # 5. Handle Caret (^)
    if clean_constraint.startswith("^"):
        target_str = clean_constraint[1:].lstrip("v").strip()
        if not target_str:
            return False, f"unsupported: empty caret target in '{constraint}'"

        has_prerelease = "-" in target_str
        target_base = target_str.split("-")[0] if has_prerelease else target_str
        parts = target_base.split(".")

        lower_v: Optional[Version] = None
        upper_v: Optional[Version] = None

        if has_prerelease:
            try:
                target_v = _parse_semver(target_str)
            except (InvalidVersion, TypeError):
                return False, f"unsupported: invalid version format in '{constraint}'"
            major, minor, micro = target_v.major, target_v.minor, target_v.micro
            lower_v = target_v
            if major > 0:
                upper_v = Version(f"{major + 1}.0.0")
            elif minor > 0:
                upper_v = Version(f"0.{minor + 1}.0")
            else:
                upper_v = Version(f"0.0.{micro + 1}")
        else:
            if len(parts) == 1:
                if parts[0] in ("*", "x", "X"):
                    lower_v = Version("0.0.0")
                    upper_v = None
                elif parts[0].isdigit():
                    m = int(parts[0])
                    if m == 0:
                        lower_v = Version("0.0.0")
                        upper_v = Version("1.0.0")
                    else:
                        lower_v = Version(f"{m}.0.0")
                        upper_v = Version(f"{m + 1}.0.0")
                else:
                    return False, f"unsupported: invalid version format in '{constraint}'"
            elif len(parts) == 2:
                if not parts[0].isdigit():
                    return False, f"unsupported: invalid version format in '{constraint}'"
                m = int(parts[0])
                if parts[1] in ("*", "x", "X"):
                    if m == 0:
                        # ^0.x means >=0.0.0 <1.0.0
                        lower_v = Version("0.0.0")
                        upper_v = Version("1.0.0")
                    else:
                        lower_v = Version(f"{m}.0.0")
                        upper_v = Version(f"{m + 1}.0.0")
                elif parts[1].isdigit():
                    n = int(parts[1])
                    if m > 0:
                        # ^1.2 means >=1.2.0 <2.0.0
                        lower_v = Version(f"{m}.{n}.0")
                        upper_v = Version(f"{m + 1}.0.0")
                    elif n > 0:
                        # ^0.2 means >=0.2.0 <0.3.0
                        lower_v = Version(f"0.{n}.0")
                        upper_v = Version(f"0.{n + 1}.0")
                    else:
                        # ^0.0 means >=0.0.0 <0.1.0
                        lower_v = Version("0.0.0")
                        upper_v = Version("0.1.0")
                else:
                    return False, f"unsupported: invalid version format in '{constraint}'"
            elif len(parts) == 3:
                if not (parts[0].isdigit() and parts[1].isdigit()):
                    return False, f"unsupported: invalid version format in '{constraint}'"
                m, n = int(parts[0]), int(parts[1])
                if parts[2] in ("*", "x", "X"):
                    if m > 0:
                        lower_v = Version(f"{m}.{n}.0")
                        upper_v = Version(f"{m + 1}.0.0")
                    elif n > 0:
                        lower_v = Version(f"0.{n}.0")
                        upper_v = Version(f"0.{n + 1}.0")
                    else:
                        lower_v = Version("0.0.0")
                        upper_v = Version("0.1.0")
                elif parts[2].isdigit():
                    try:
                        target_v = _parse_semver(target_str)
                    except (InvalidVersion, TypeError):
                        return False, f"unsupported: invalid version format in '{constraint}'"
                    major, minor, micro = target_v.major, target_v.minor, target_v.micro
                    lower_v = target_v
                    if major > 0:
                        upper_v = Version(f"{major + 1}.0.0")
                    elif minor > 0:
                        upper_v = Version(f"0.{minor + 1}.0")
                    else:
                        upper_v = Version(f"0.0.{micro + 1}")
                else:
                    return False, f"unsupported: invalid version format in '{constraint}'"
            else:
                return False, f"unsupported: invalid version format in '{constraint}'"

        # Prerelease exclusion rules:
        if ver.is_prerelease:
            if not has_prerelease:
                return False, f"drift: prerelease version '{version_str}' does not satisfy caret range '{constraint}' without matching prerelease tuple"
            target_v = _parse_semver(target_str)
            if (ver.major, ver.minor, ver.micro) != (target_v.major, target_v.minor, target_v.micro):
                return False, f"drift: prerelease version '{version_str}' does not satisfy caret range '{constraint}' without matching prerelease tuple"

        if upper_v is not None:
            if ver >= lower_v and ver < upper_v:
                return True, None
            return False, f"drift: resolved version '{version_str}' does not satisfy caret range '{constraint}' (expected >={lower_v}, <{upper_v})"
        else:
            if ver >= lower_v:
                return True, None
            return False, f"drift: resolved version '{version_str}' does not satisfy caret range '{constraint}'"

    # 6. Handle Tilde (~)
    if clean_constraint.startswith("~"):
        target_str = clean_constraint[1:].lstrip("v").strip()
        if not target_str:
            return False, f"unsupported: empty tilde target in '{constraint}'"

        has_prerelease = "-" in target_str
        target_base = target_str.split("-")[0] if has_prerelease else target_str
        parts = target_base.split(".")

        lower_v: Optional[Version] = None
        upper_v: Optional[Version] = None

        if has_prerelease:
            try:
                target_v = _parse_semver(target_str)
            except (InvalidVersion, TypeError):
                return False, f"unsupported: invalid version format in '{constraint}'"
            major, minor = target_v.major, target_v.minor
            lower_v = target_v
            upper_v = Version(f"{major}.{minor + 1}.0")
        else:
            if len(parts) == 1:
                if parts[0] in ("*", "x", "X"):
                    lower_v = Version("0.0.0")
                    upper_v = None
                elif parts[0].isdigit():
                    m = int(parts[0])
                    # ~1 means >=1.0.0 <2.0.0
                    lower_v = Version(f"{m}.0.0")
                    upper_v = Version(f"{m + 1}.0.0")
                else:
                    return False, f"unsupported: invalid version format in '{constraint}'"
            elif len(parts) == 2:
                if not parts[0].isdigit():
                    return False, f"unsupported: invalid version format in '{constraint}'"
                m = int(parts[0])
                if parts[1] in ("*", "x", "X"):
                    lower_v = Version(f"{m}.0.0")
                    upper_v = Version(f"{m + 1}.0.0")
                elif parts[1].isdigit():
                    n = int(parts[1])
                    # ~1.2 means >=1.2.0 <1.3.0
                    lower_v = Version(f"{m}.{n}.0")
                    upper_v = Version(f"{m}.{n + 1}.0")
                else:
                    return False, f"unsupported: invalid version format in '{constraint}'"
            elif len(parts) == 3:
                if not (parts[0].isdigit() and parts[1].isdigit()):
                    return False, f"unsupported: invalid version format in '{constraint}'"
                m, n = int(parts[0]), int(parts[1])
                if parts[2] in ("*", "x", "X"):
                    lower_v = Version(f"{m}.{n}.0")
                    upper_v = Version(f"{m}.{n + 1}.0")
                elif parts[2].isdigit():
                    try:
                        target_v = _parse_semver(target_str)
                    except (InvalidVersion, TypeError):
                        return False, f"unsupported: invalid version format in '{constraint}'"
                    major, minor = target_v.major, target_v.minor
                    lower_v = target_v
                    upper_v = Version(f"{major}.{minor + 1}.0")
                else:
                    return False, f"unsupported: invalid version format in '{constraint}'"
            else:
                return False, f"unsupported: invalid version format in '{constraint}'"

        if ver.is_prerelease:
            if not has_prerelease:
                return False, f"drift: prerelease version '{version_str}' does not satisfy tilde range '{constraint}' without matching prerelease tuple"
            target_v = _parse_semver(target_str)
            if (ver.major, ver.minor, ver.micro) != (target_v.major, target_v.minor, target_v.micro):
                return False, f"drift: prerelease version '{version_str}' does not satisfy tilde range '{constraint}' without matching prerelease tuple"

        if upper_v is not None:
            if ver >= lower_v and ver < upper_v:
                return True, None
            return False, f"drift: resolved version '{version_str}' does not satisfy tilde range '{constraint}' (expected >={lower_v}, <{upper_v})"
        else:
            if ver >= lower_v:
                return True, None
            return False, f"drift: resolved version '{version_str}' does not satisfy tilde range '{constraint}'"

    # 7. Comparators, Partial Versions, and Exact Versions
    clauses = clean_constraint.split()

    # Exclude prereleases unless a comparator explicitly specifies a prerelease on the same tuple
    if ver.is_prerelease:
        has_matching_prerelease_clause = False
        for cl in clauses:
            raw_t = cl.lstrip("<=>").lstrip("v").strip()
            if "-" in raw_t:
                try:
                    cl_v = _parse_semver(raw_t)
                    if cl_v.is_prerelease and (cl_v.major, cl_v.minor, cl_v.micro) == (ver.major, ver.minor, ver.micro):
                        has_matching_prerelease_clause = True
                        break
                except Exception:
                    pass
        if not has_matching_prerelease_clause:
            return False, f"drift: prerelease version '{version_str}' does not satisfy range '{constraint}' without matching prerelease comparator tuple"

    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue
        try:
            if clause.startswith("<="):
                target_str = clause[2:].lstrip("v").strip()
                partial = _expand_partial_version(target_str)
                if partial:
                    upper = partial[1]
                    if upper is not None and not (ver < upper):
                        return False, f"drift: '{version_str}' is not <= '{target_str}'"
                else:
                    if not (ver <= _parse_semver(target_str)):
                        return False, f"drift: '{version_str}' is not <= '{target_str}'"
            elif clause.startswith("<"):
                target_str = clause[1:].lstrip("v").strip()
                partial = _expand_partial_version(target_str)
                if partial:
                    lower = partial[0]
                    if not (ver < lower):
                        return False, f"drift: '{version_str}' is not < '{target_str}'"
                else:
                    if not (ver < _parse_semver(target_str)):
                        return False, f"drift: '{version_str}' is not < '{target_str}'"
            elif clause.startswith(">="):
                target_str = clause[2:].lstrip("v").strip()
                partial = _expand_partial_version(target_str)
                if partial:
                    lower = partial[0]
                    if not (ver >= lower):
                        return False, f"drift: '{version_str}' is not >= '{target_str}'"
                else:
                    if not (ver >= _parse_semver(target_str)):
                        return False, f"drift: '{version_str}' is not >= '{target_str}'"
            elif clause.startswith(">"):
                target_str = clause[1:].lstrip("v").strip()
                partial = _expand_partial_version(target_str)
                if partial:
                    upper = partial[1]
                    if upper is not None:
                        if not (ver >= upper):
                            return False, f"drift: '{version_str}' is not > '{target_str}'"
                    else:
                        return False, f"drift: '{version_str}' is not > '{target_str}'"
                else:
                    if not (ver > _parse_semver(target_str)):
                        return False, f"drift: '{version_str}' is not > '{target_str}'"
            elif clause.startswith("==") or clause.startswith("="):
                target_str = clause.lstrip("=").lstrip("v").strip()
                partial = _expand_partial_version(target_str)
                if partial:
                    lower, upper = partial
                    if upper is not None:
                        if not (lower <= ver < upper):
                            return False, f"drift: '{version_str}' does not satisfy '{clause}'"
                    else:
                        if not (ver >= lower):
                            return False, f"drift: '{version_str}' does not satisfy '{clause}'"
                else:
                    if not (ver == _parse_semver(target_str)):
                        return False, f"drift: '{version_str}' is not == '{target_str}'"
            else:
                target_str = clause.lstrip("v").strip()
                partial = _expand_partial_version(target_str)
                if partial:
                    lower, upper = partial
                    if upper is not None:
                        if not (lower <= ver < upper):
                            return False, f"drift: '{version_str}' does not satisfy '{clause}' (expected >={lower}, <{upper})"
                    else:
                        if not (ver >= lower):
                            return False, f"drift: '{version_str}' does not satisfy '{clause}'"
                else:
                    target_v = _parse_semver(target_str)
                    if not (ver == target_v):
                        return False, f"drift: '{version_str}' does not equal exact declared version '{target_str}'"
        except (InvalidVersion, TypeError):
            return False, f"unsupported: invalid version format in clause '{clause}'"

    return True, None


def _extract_pkg_name_from_path(pkg_path: str) -> str:
    """
    Extracts canonical package name from node_modules path.
    Handles:
      'node_modules/express' -> 'express'
      'node_modules/@types/node' -> '@types/node'
      'node_modules/express/node_modules/debug' -> 'debug'
      'node_modules/express/node_modules/@scope/pkg' -> '@scope/pkg'
    """
    parts = pkg_path.split("node_modules/")
    last_segment = parts[-1].rstrip("/")
    return last_segment


def parse_package_lock_json(
    lock_file_path: str,
    package_json_path: Optional[str] = None,
    root_app_id: Optional[str] = None
) -> NpmLockfileResult:
    """
    Authoritative parser for package-lock.json supporting v2 and v3 format.
    Cross-references with package.json when available to classify direct vs dev vs transitive.
    """
    if not os.path.exists(lock_file_path):
        raise FileNotFoundError(f"package-lock.json not found: {lock_file_path}")

    with open(lock_file_path, "r", encoding="utf-8") as f:
        lock_data = json.load(f)

    lockfile_version = lock_data.get("lockfileVersion", 1)
    project_name = lock_data.get("name", "unknown")

    manifest_deps: Dict[str, str] = {}
    manifest_dev_deps: Dict[str, str] = {}

    if package_json_path and os.path.exists(package_json_path):
        detailed = parse_package_json_detailed(package_json_path)
        manifest_deps = detailed["dependencies"]
        manifest_dev_deps = detailed["devDependencies"]
        if detailed["name"] != "unknown":
            project_name = detailed["name"]

    packages_map: Dict[str, NpmPackage] = {}
    inconsistencies: List[str] = []
    warnings: List[str] = []

    # Handle lockfileVersion 2 & 3: uses 'packages' dict
    if "packages" in lock_data:
        raw_packages = lock_data.get("packages", {})

        # Root entry in packages is ""
        root_pkg = raw_packages.get("", {})
        if not manifest_deps:
            manifest_deps = root_pkg.get("dependencies", {}) or {}
        if not manifest_dev_deps:
            manifest_dev_deps = root_pkg.get("devDependencies", {}) or {}

        # First pass: parse all packages
        for pkg_path, entry in raw_packages.items():
            if pkg_path == "":
                continue

            name = entry.get("name") or _extract_pkg_name_from_path(pkg_path)
            version = entry.get("version", "")
            if not version:
                inconsistencies.append(f"Package '{name}' at path '{pkg_path}' is missing resolved version")
                continue

            is_dev = bool(entry.get("dev", False))
            # Direct if it sits at root node_modules/ and is in manifest_deps or manifest_dev_deps
            is_top_level = pkg_path == f"node_modules/{name}"
            is_direct_prod = is_top_level and name in manifest_deps
            is_direct_dev = is_top_level and name in manifest_dev_deps
            is_direct = is_direct_prod or is_direct_dev

            declared_deps = entry.get("dependencies", {}) or {}

            pkg = NpmPackage(
                name=name,
                version=version,
                path=pkg_path,
                is_direct=is_direct,
                is_dev=is_dev or is_direct_dev,
                resolved=entry.get("resolved"),
                integrity=entry.get("integrity"),
                declared_dependencies=declared_deps,
            )
            packages_map[pkg_path] = pkg

    # Fallback / Hybrid for lockfileVersion 1 or missing packages dict
    elif "dependencies" in lock_data:
        def _parse_v1_deps(deps_tree: Dict[str, Any], prefix: str = "node_modules"):
            for name, entry in deps_tree.items():
                pkg_path = f"{prefix}/{name}"
                version = entry.get("version", "")
                is_dev = bool(entry.get("dev", False))
                is_direct = (prefix == "node_modules") and (name in manifest_deps or name in manifest_dev_deps)

                sub_deps = entry.get("dependencies", {})
                declared_deps_map = {k: v.get("version", "") for k, v in sub_deps.items()}

                pkg = NpmPackage(
                    name=name,
                    version=version,
                    path=pkg_path,
                    is_direct=is_direct,
                    is_dev=is_dev,
                    resolved=entry.get("resolved"),
                    integrity=entry.get("integrity"),
                    declared_dependencies=declared_deps_map
                )
                packages_map[pkg_path] = pkg

                if sub_deps:
                    _parse_v1_deps(sub_deps, prefix=f"{pkg_path}/node_modules")

        _parse_v1_deps(lock_data.get("dependencies", {}))

    # Validate that every manifest-declared direct dependency exists as an actual root direct package entry
    for declared_pkg, req_range in manifest_deps.items():
        expected_path = f"node_modules/{declared_pkg}"
        top_pkg = packages_map.get(expected_path)
        if not top_pkg or not top_pkg.is_direct:
            inconsistencies.append(
                f"Declared direct production dependency '{declared_pkg}' ({req_range}) is missing root package entry from lockfile at '{expected_path}'"
            )
            warnings.append(
                f"Declared direct production dependency '{declared_pkg}' ({req_range}) is missing root package entry from lockfile at '{expected_path}'"
            )
        else:
            ok, reason = check_npm_version_satisfies(top_pkg.version, req_range)
            if not ok:
                msg = f"Declared production dependency '{declared_pkg}' ({req_range}) lockfile mismatch: {reason}"
                inconsistencies.append(msg)
                warnings.append(msg)

    for declared_pkg, req_range in manifest_dev_deps.items():
        expected_path = f"node_modules/{declared_pkg}"
        top_pkg = packages_map.get(expected_path)
        if not top_pkg or not top_pkg.is_direct:
            inconsistencies.append(
                f"Declared direct devDependency '{declared_pkg}' ({req_range}) is missing root package entry from lockfile at '{expected_path}'"
            )
            warnings.append(
                f"Declared direct devDependency '{declared_pkg}' ({req_range}) is missing root package entry from lockfile at '{expected_path}'"
            )
        else:
            ok, reason = check_npm_version_satisfies(top_pkg.version, req_range)
            if not ok:
                msg = f"Declared devDependency '{declared_pkg}' ({req_range}) lockfile mismatch: {reason}"
                inconsistencies.append(msg)
                warnings.append(msg)

    # Second pass: resolve dependency relationships (edges)
    # Consumer -> Dependency
    dependency_edges: List[Dict[str, str]] = []

    # Map name -> list of installed packages (supports multiple versions at different paths)
    name_to_pkgs: Dict[str, List[NpmPackage]] = {}
    for pkg in packages_map.values():
        name_to_pkgs.setdefault(pkg.name, []).append(pkg)

    # 1. Project Root -> Direct Dependencies
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

    # 2. Package -> Transitive Dependencies
    for parent_pkg in packages_map.values():
        for req_dep_name, req_semver in parent_pkg.declared_dependencies.items():
            # Look for locally nested candidate first (e.g. parent/node_modules/child)
            nested_path = f"{parent_pkg.path}/node_modules/{req_dep_name}"
            target_pkg = packages_map.get(nested_path)

            # Otherwise look at top-level node_modules/child
            if not target_pkg:
                top_path = f"node_modules/{req_dep_name}"
                target_pkg = packages_map.get(top_path)

            # If still not found, check any matching package name
            if not target_pkg and req_dep_name in name_to_pkgs:
                target_pkg = name_to_pkgs[req_dep_name][0]

            if target_pkg:
                parent_pkg.resolved_dependency_keys.append(target_pkg.id)
                dependency_edges.append({
                    "source": parent_pkg.id,
                    "target": target_pkg.id,
                    "relation": "transitive_dependency",
                    "consumer_name": parent_pkg.name,
                    "dependency_name": target_pkg.name,
                    "dependency_version": target_pkg.version
                })
            else:
                warnings.append(
                    f"Transitive dependency '{req_dep_name}' ({req_semver}) required by '{parent_pkg.name}' was not found in lockfile"
                )

    direct_list = [p for p in packages_map.values() if p.is_direct and not p.is_dev]
    dev_list = [p for p in packages_map.values() if p.is_dev]
    transitive_list = [p for p in packages_map.values() if not p.is_direct]

    return NpmLockfileResult(
        project_name=project_name,
        lockfile_version=lockfile_version,
        packages=packages_map,
        direct_packages=direct_list,
        dev_packages=dev_list,
        transitive_packages=transitive_list,
        dependency_edges=dependency_edges,
        inconsistencies=inconsistencies,
        warnings=warnings
    )
