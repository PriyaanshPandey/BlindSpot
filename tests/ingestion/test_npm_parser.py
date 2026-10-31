"""
Unit tests for NPM Dependency Parsing [Role A].
Tests package.json, package-lock.json v2/v3, scoped packages, multiple versions,
transitive dependency tracking, and lockfile inconsistency detection.
"""

import json
import pytest
from app.ingestion.npm_parser import (
    parse_package_json,
    parse_package_json_detailed,
    parse_package_lock_json,
    check_npm_version_satisfies,
    NpmLockfileResult
)


def test_parse_package_json_backward_compatible(tmp_path):
    """Verifies that existing callers of parse_package_json continue to work unchanged."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "name": "my-service",
        "dependencies": {"express": "^4.19.2", "stripe": "^15.0.0"},
        "devDependencies": {"nodemon": "^3.1.0"}
    }))

    result = parse_package_json(str(pkg_file))
    assert result["name"] == "my-service"
    assert "express" in result["dependencies"]
    assert "stripe" in result["dependencies"]
    assert "nodemon" in result["dependencies"]
    assert result["dependencies"]["express"] == "^4.19.2"


def test_parse_package_json_detailed(tmp_path):
    """Verifies detailed segregation of prod and dev dependencies."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "name": "detailed-service",
        "version": "1.2.3",
        "dependencies": {"axios": "^1.7.0"},
        "devDependencies": {"jest": "^29.0.0"}
    }))

    detailed = parse_package_json_detailed(str(pkg_file))
    assert detailed["name"] == "detailed-service"
    assert "axios" in detailed["dependencies"]
    assert "jest" in detailed["devDependencies"]
    assert "jest" not in detailed["dependencies"]


def test_lockfile_v3_parsing_and_resolution(tmp_path):
    """Verifies lockfileVersion 3 parsing with direct, dev, and transitive dependencies."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "nexus-store",
        "dependencies": {"express": "^4.19.0"},
        "devDependencies": {"typescript": "^5.4.0"}
    }))

    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "nexus-store",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "nexus-store",
                "dependencies": {"express": "^4.19.0"},
                "devDependencies": {"typescript": "^5.4.0"}
            },
            "node_modules/express": {
                "version": "4.19.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
                "integrity": "sha512-abc",
                "dependencies": {
                    "qs": "6.11.0"
                }
            },
            "node_modules/qs": {
                "version": "6.11.0",
                "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz"
            },
            "node_modules/typescript": {
                "version": "5.4.5",
                "dev": True,
                "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.4.5.tgz"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json), package_json_path=str(pkg_json))

    assert result.project_name == "nexus-store"
    assert result.lockfile_version == 3
    assert result.is_consistent is True

    # Check direct production dependency
    express_pkg = result.packages["node_modules/express"]
    assert express_pkg.name == "express"
    assert express_pkg.version == "4.19.2"  # Exact resolved version, NOT ^4.19.0
    assert express_pkg.is_direct is True
    assert express_pkg.is_dev is False

    # Check dev dependency
    ts_pkg = result.packages["node_modules/typescript"]
    assert ts_pkg.name == "typescript"
    assert ts_pkg.version == "5.4.5"
    assert ts_pkg.is_dev is True

    # Check transitive dependency
    qs_pkg = result.packages["node_modules/qs"]
    assert qs_pkg.name == "qs"
    assert qs_pkg.version == "6.11.0"
    assert qs_pkg.is_direct is False

    # Check edges
    edge_relations = [(e["source"], e["target"], e["relation"]) for e in result.dependency_edges]
    # Root -> express (depends_on)
    assert any(e[0] == "app:nexus-store" and "pkg:npm/express" in e[1] and e[2] == "depends_on" for e in edge_relations)
    # express -> qs (transitive_dependency)
    assert any("pkg:npm/express" in e[0] and "pkg:npm/qs" in e[1] and e[2] == "transitive_dependency" for e in edge_relations)


def test_scoped_packages(tmp_path):
    """Verifies handling of scoped NPM packages (@scope/name)."""
    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "scoped-demo",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"@types/node": "^20.12.0", "@fastify/cors": "^9.0.1"}
            },
            "node_modules/@types/node": {
                "version": "20.12.7"
            },
            "node_modules/@fastify/cors": {
                "version": "9.0.1"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json))
    assert "node_modules/@types/node" in result.packages
    assert result.packages["node_modules/@types/node"].name == "@types/node"
    assert result.packages["node_modules/@types/node"].version == "20.12.7"
    assert result.packages["node_modules/@fastify/cors"].name == "@fastify/cors"


def test_multiple_installed_versions(tmp_path):
    """Verifies tracking of multiple installed versions of the same package at different paths."""
    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "multi-version-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"legacy-lib": "^1.0.0", "modern-lib": "^2.0.0"}
            },
            "node_modules/shared-util": {
                "version": "1.0.0"
            },
            "node_modules/legacy-lib": {
                "version": "1.2.0",
                "dependencies": {"shared-util": "1.0.0"}
            },
            "node_modules/modern-lib": {
                "version": "2.1.0",
                "dependencies": {"shared-util": "2.0.0"}
            },
            "node_modules/modern-lib/node_modules/shared-util": {
                "version": "2.0.0"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json))
    # Both paths exist distinctly
    assert "node_modules/shared-util" in result.packages
    assert "node_modules/modern-lib/node_modules/shared-util" in result.packages

    v1_pkg = result.packages["node_modules/shared-util"]
    v2_pkg = result.packages["node_modules/modern-lib/node_modules/shared-util"]
    assert v1_pkg.version == "1.0.0"
    assert v2_pkg.version == "2.0.0"
    assert v1_pkg.id != v2_pkg.id


def test_detect_inconsistent_lockfile(tmp_path):
    """Verifies that packages declared in package.json but absent in package-lock.json are detected."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "drift-app",
        "dependencies": {"express": "^4.19.0", "missing-pkg": "^2.0.0"},
        "devDependencies": {"missing-dev-pkg": "^1.0.0"}
    }))

    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "drift-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"express": "^4.19.0"}
            },
            "node_modules/express": {
                "version": "4.19.2"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json), package_json_path=str(pkg_json))
    assert result.is_consistent is False
    assert any("missing-pkg" in inc for inc in result.inconsistencies)
    assert any("missing-dev-pkg" in inc for inc in result.inconsistencies)


def test_check_npm_version_satisfies_unit():
    """Unit tests for check_npm_version_satisfies across all common NPM range types."""
    # Valid ranges
    assert check_npm_version_satisfies("4.19.2", "^4.18.0")[0] is True
    assert check_npm_version_satisfies("1.2.4", "~1.2.0")[0] is True
    assert check_npm_version_satisfies("2.4.3", ">=2.0.0 <3.0.0")[0] is True
    assert check_npm_version_satisfies("1.5.0", "1.0.0 - 2.0.0")[0] is True
    assert check_npm_version_satisfies("1.3.0", "1.x")[0] is True
    assert check_npm_version_satisfies("9.9.9", "*")[0] is True

    # Version drift
    ok, reason = check_npm_version_satisfies("8.5.1", "^9.0.0")
    assert ok is False
    assert "drift:" in reason

    ok, reason = check_npm_version_satisfies("1.3.0", "~1.2.0")
    assert ok is False
    assert "drift:" in reason

    ok, reason = check_npm_version_satisfies("2.0.0", "1.0.0")
    assert ok is False
    assert "drift:" in reason

    # Unsupported constraints
    ok, reason = check_npm_version_satisfies("1.0.0", "git+https://github.com/foo/bar.git")
    assert ok is False
    assert "unsupported:" in reason

    ok, reason = check_npm_version_satisfies("1.0.0", "beta")
    assert ok is False
    assert "unsupported:" in reason

    # Prerelease and build metadata
    ok, _ = check_npm_version_satisfies("1.0.0-beta.2", "^1.0.0-beta.1")
    assert ok is True

    ok, _ = check_npm_version_satisfies("1.0.0+20130313144700", "1.0.0")
    assert ok is True


def test_npm_lockfile_version_drift_integration(tmp_path):
    """
    Regression test for Requirement 5:
    package.json declares jsonwebtoken: ^9.0.0
    package-lock.json resolves jsonwebtoken@8.5.1
    This must NOT be reported as a consistent lockfile.
    """
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "auth-service",
        "dependencies": {"jsonwebtoken": "^9.0.0"}
    }))

    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "auth-service",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"jsonwebtoken": "^9.0.0"}
            },
            "node_modules/jsonwebtoken": {
                "version": "8.5.1"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json), package_json_path=str(pkg_json))
    assert result.is_consistent is False
    assert any("jsonwebtoken" in inc and "lockfile mismatch" in inc for inc in result.inconsistencies)
    assert any("drift" in w for w in result.warnings)


def test_npm_lockfile_valid_range_satisfaction(tmp_path):
    """Verifies that a resolved version satisfying the declared range is reported consistent."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "auth-service",
        "dependencies": {"jsonwebtoken": "^8.5.0"}
    }))

    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "auth-service",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"jsonwebtoken": "^8.5.0"}
            },
            "node_modules/jsonwebtoken": {
                "version": "8.5.1"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json), package_json_path=str(pkg_json))
    assert result.is_consistent is True
    assert len(result.inconsistencies) == 0


def test_npm_lockfile_unsupported_range_warning(tmp_path):
    """Verifies that unsupported range expressions emit a clear warning and are not reported as consistent."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "custom-app",
        "dependencies": {"custom-pkg": "git+https://github.com/org/custom-pkg.git"}
    }))

    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "custom-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"custom-pkg": "git+https://github.com/org/custom-pkg.git"}
            },
            "node_modules/custom-pkg": {
                "version": "1.0.0"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json), package_json_path=str(pkg_json))
    assert result.is_consistent is False
    assert any("unsupported" in inc for inc in result.inconsistencies)
    assert any("unsupported" in w for w in result.warnings)


def test_npm_prerelease_exclusion_rules():
    """
    Regression test for Command A1.3 Requirement 1:
    - 1.1.0-beta.1 must NOT satisfy ^1.0.0
    - 2.0.0-beta.1 must NOT satisfy ^1.0.0
    - 1.2.3-beta.2 must satisfy an explicitly prerelease-compatible range for 1.2.3
    - Stable versions must continue to match appropriate ranges
    - Build metadata must not affect version precedence
    """
    # 1. 1.1.0-beta.1 must NOT satisfy ^1.0.0
    ok, reason = check_npm_version_satisfies("1.1.0-beta.1", "^1.0.0")
    assert ok is False
    assert "prerelease" in reason

    # 2. 2.0.0-beta.1 must NOT satisfy ^1.0.0
    ok, reason = check_npm_version_satisfies("2.0.0-beta.1", "^1.0.0")
    assert ok is False
    assert "prerelease" in reason

    # 3. 1.2.3-beta.2 must satisfy an explicitly prerelease-compatible range for 1.2.3
    ok1, _ = check_npm_version_satisfies("1.2.3-beta.2", "^1.2.3-beta.1")
    assert ok1 is True

    ok2, _ = check_npm_version_satisfies("1.2.3-beta.2", ">=1.2.3-beta.1 <1.3.0")
    assert ok2 is True

    ok3, _ = check_npm_version_satisfies("1.2.3-beta.2", "1.2.3-beta.2")
    assert ok3 is True

    # But 1.2.4-beta.1 does NOT satisfy ^1.2.3-beta.1 because tuple (1, 2, 4) != (1, 2, 3)
    ok4, _ = check_npm_version_satisfies("1.2.4-beta.1", "^1.2.3-beta.1")
    assert ok4 is False

    # 4. Stable versions must continue to match appropriate ranges
    ok_stable1, _ = check_npm_version_satisfies("1.1.0", "^1.0.0")
    assert ok_stable1 is True

    ok_stable2, _ = check_npm_version_satisfies("1.2.4", "^1.2.3-beta.1")
    assert ok_stable2 is True

    # 5. Build metadata must not affect version precedence
    ok_b1, _ = check_npm_version_satisfies("1.0.0+build.1", "1.0.0")
    assert ok_b1 is True

    ok_b2, _ = check_npm_version_satisfies("1.0.0", "1.0.0+build.2")
    assert ok_b2 is True

    ok_b3, _ = check_npm_version_satisfies("1.0.0+build.1", "1.0.0+build.2")
    assert ok_b3 is True


def test_npm_direct_dependency_integrity_regression(tmp_path):
    """
    Regression test for Command A1.3 Requirement 3:
    Manifest declares foo: ^2.0.0.
    Lockfile has only node_modules/other/node_modules/foo@1.2.3.
    No root-level node_modules/foo exists.
    Expected:
    - Lockfile inconsistent.
    - Missing direct package diagnostic.
    - No fabricated root-to-foo direct dependency edge.
    """
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "my-integrity-app",
        "dependencies": {
            "foo": "^2.0.0"
        }
    }))

    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text(json.dumps({
        "name": "my-integrity-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"foo": "^2.0.0"}
            },
            "node_modules/other": {
                "version": "1.0.0",
                "dependencies": {"foo": "1.2.3"}
            },
            "node_modules/other/node_modules/foo": {
                "version": "1.2.3"
            }
        }
    }))

    result = parse_package_lock_json(str(lock_json), package_json_path=str(pkg_json))

    # 1. Lockfile must be reported as inconsistent
    assert result.is_consistent is False

    # 2. Missing direct package diagnostic
    assert any("foo" in inc and "missing" in inc for inc in result.inconsistencies), (
        f"Expected missing direct package diagnostic in inconsistencies: {result.inconsistencies}"
    )

    # 3. No fabricated root-to-foo direct dependency edge
    root_to_foo_edges = [
        e for e in result.dependency_edges
        if e["source"] == "app:my-integrity-app" and e.get("dependency_name") == "foo"
    ]
    assert len(root_to_foo_edges) == 0, (
        f"Fabricated root-to-foo direct edge was created: {root_to_foo_edges}"
    )


def test_npm_partial_version_semantics():
    """
    Regression tests for Command A1.4 Requirement 2:
    - 1 means >=1.0.0 <2.0.0 (not exact 1.0.0)
    - 1.2 means >=1.2.0 <1.3.0 (not exact 1.2.0)
    - ~1 means >=1.0.0 <2.0.0
    - ~1.2 means >=1.2.0 <1.3.0
    - ^0.0 means >=0.0.0 <0.1.0
    - ^0.x means >=0.0.0 <1.0.0
    - Prerelease exclusion and build metadata rules preserved.
    """
    # 1: >=1.0.0 <2.0.0
    assert check_npm_version_satisfies("1.0.0", "1")[0] is True
    assert check_npm_version_satisfies("1.2.3", "1")[0] is True
    assert check_npm_version_satisfies("1.9.9", "1")[0] is True
    assert check_npm_version_satisfies("0.9.9", "1")[0] is False
    assert check_npm_version_satisfies("2.0.0", "1")[0] is False
    # Ensure 1 is NOT treated as exact 1.0.0
    ok, _ = check_npm_version_satisfies("1.5.0", "1")
    assert ok is True

    # 1.2: >=1.2.0 <1.3.0
    assert check_npm_version_satisfies("1.2.0", "1.2")[0] is True
    assert check_npm_version_satisfies("1.2.4", "1.2")[0] is True
    assert check_npm_version_satisfies("1.1.9", "1.2")[0] is False
    assert check_npm_version_satisfies("1.3.0", "1.2")[0] is False
    # Ensure 1.2 is NOT treated as exact 1.2.0
    ok, _ = check_npm_version_satisfies("1.2.9", "1.2")
    assert ok is True

    # ~1: >=1.0.0 <2.0.0
    assert check_npm_version_satisfies("1.0.0", "~1")[0] is True
    assert check_npm_version_satisfies("1.8.2", "~1")[0] is True
    assert check_npm_version_satisfies("0.9.9", "~1")[0] is False
    assert check_npm_version_satisfies("2.0.0", "~1")[0] is False

    # ~1.2: >=1.2.0 <1.3.0
    assert check_npm_version_satisfies("1.2.0", "~1.2")[0] is True
    assert check_npm_version_satisfies("1.2.9", "~1.2")[0] is True
    assert check_npm_version_satisfies("1.1.9", "~1.2")[0] is False
    assert check_npm_version_satisfies("1.3.0", "~1.2")[0] is False

    # ^0.0: >=0.0.0 <0.1.0
    assert check_npm_version_satisfies("0.0.0", "^0.0")[0] is True
    assert check_npm_version_satisfies("0.0.4", "^0.0")[0] is True
    assert check_npm_version_satisfies("0.0.9", "^0.0")[0] is True
    assert check_npm_version_satisfies("0.1.0", "^0.0")[0] is False
    assert check_npm_version_satisfies("1.0.0", "^0.0")[0] is False

    # ^0.x: >=0.0.0 <1.0.0
    assert check_npm_version_satisfies("0.0.0", "^0.x")[0] is True
    assert check_npm_version_satisfies("0.5.2", "^0.x")[0] is True
    assert check_npm_version_satisfies("0.9.9", "^0.x")[0] is True
    assert check_npm_version_satisfies("1.0.0", "^0.x")[0] is False

    # Prerelease exclusion with partial versions
    ok, reason = check_npm_version_satisfies("1.2.0-beta.1", "1")
    assert ok is False
    assert "prerelease" in reason

    ok, reason = check_npm_version_satisfies("1.2.5-alpha", "1.2")
    assert ok is False
    assert "prerelease" in reason

    # Build metadata handling
    assert check_npm_version_satisfies("1.2.0+build.42", "1.2")[0] is True
    assert check_npm_version_satisfies("1.5.0+exp.sha", "1")[0] is True


def test_npm_logical_or_parsing():
    """
    Regression tests for Command A1.4 Requirement 3:
    - Logical OR (||) processed before individual caret, tilde, wildcard or comparator parsing.
    - Tests for:
      - ^1.0.0 || ^2.0.0
      - 1.x || 2.x
      - ^1.2.0 || ~3.0
      - A version matching only the second alternative.
      - A version matching neither alternative.
    - Each alternative is evaluated independently.
    - Unsupported expressions return an explicit warning rather than being silently accepted.
    """
    # 1. ^1.0.0 || ^2.0.0
    # Matching first alternative
    assert check_npm_version_satisfies("1.5.0", "^1.0.0 || ^2.0.0")[0] is True
    # Matching only the second alternative
    assert check_npm_version_satisfies("2.1.0", "^1.0.0 || ^2.0.0")[0] is True
    # Matching neither alternative
    ok, reason = check_npm_version_satisfies("3.0.0", "^1.0.0 || ^2.0.0")
    assert ok is False
    assert "drift:" in reason
    assert "union range" in reason

    # 2. 1.x || 2.x
    assert check_npm_version_satisfies("1.4.0", "1.x || 2.x")[0] is True
    assert check_npm_version_satisfies("2.8.1", "1.x || 2.x")[0] is True
    assert check_npm_version_satisfies("0.9.0", "1.x || 2.x")[0] is False
    assert check_npm_version_satisfies("3.0.0", "1.x || 2.x")[0] is False

    # 3. ^1.2.0 || ~3.0
    # Matching first alternative (^1.2.0: >=1.2.0 <2.0.0)
    assert check_npm_version_satisfies("1.3.0", "^1.2.0 || ~3.0")[0] is True
    # Matching only the second alternative (~3.0: >=3.0.0 <3.1.0)
    assert check_npm_version_satisfies("3.0.5", "^1.2.0 || ~3.0")[0] is True
    # Matching neither alternative (e.g. 3.1.0 is outside ~3.0, 2.0.0 is outside ^1.2.0)
    assert check_npm_version_satisfies("3.1.0", "^1.2.0 || ~3.0")[0] is False
    assert check_npm_version_satisfies("2.0.0", "^1.2.0 || ~3.0")[0] is False

    # 4. Each alternative evaluated independently and unsupported expressions return explicit warning
    # Even if the version matches the first alternative, an unsupported second alternative must emit a warning
    ok, reason = check_npm_version_satisfies("1.2.0", "^1.0.0 || git+https://github.com/foo/bar.git")
    assert ok is False
    assert "unsupported:" in reason

    # Unsupported alternative when neither matches
    ok, reason = check_npm_version_satisfies("3.0.0", "^1.0.0 || git+https://github.com/foo/bar.git")
    assert ok is False
    assert "unsupported:" in reason

    # Dist-tag alternative
    ok, reason = check_npm_version_satisfies("2.0.0", "latest || ^2.0.0")
    assert ok is False
    assert "unsupported:" in reason
    assert "dist-tag" in reason

    # Empty alternative in ||
    ok, reason = check_npm_version_satisfies("1.0.0", "^1.0.0 || ")
    assert ok is False
    assert "unsupported:" in reason

    # Invalid version in alternative
    ok, reason = check_npm_version_satisfies("1.0.0", "^1.0.0 || not_a_valid_semver")
    assert ok is False
    assert "unsupported:" in reason



