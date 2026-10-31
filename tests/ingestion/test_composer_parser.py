"""
Unit tests for Composer Dependency Parsing [Role A].
Tests composer.json and composer.lock parsing, platform requirement filtering,
transitive dependency tracking, and inconsistency detection.
"""

import json
import pytest
from app.ingestion.composer_parser import (
    parse_composer_json,
    parse_composer_lock,
    check_composer_version_satisfies,
    ComposerLockfileResult
)


def test_parse_composer_json(tmp_path):
    """Verifies that composer.json separates packages from PHP platform requirements."""
    f = tmp_path / "composer.json"
    f.write_text(json.dumps({
        "name": "nexus/legacy-api",
        "description": "Legacy microservice",
        "require": {
            "php": ">=8.1",
            "ext-json": "*",
            "guzzlehttp/guzzle": "^7.8.0",
            "monolog/monolog": "^2.9.0"
        },
        "require-dev": {
            "phpunit/phpunit": "^10.0"
        }
    }))

    res = parse_composer_json(str(f))
    assert res["name"] == "nexus/legacy-api"
    assert "guzzlehttp/guzzle" in res["dependencies"]
    assert "monolog/monolog" in res["dependencies"]
    assert "php" not in res["dependencies"]
    assert "ext-json" not in res["dependencies"]
    assert res["platformRequirements"]["php"] == ">=8.1"
    assert "phpunit/phpunit" in res["devDependencies"]


def test_parse_composer_lock_transitive_and_direct(tmp_path):
    """Verifies composer.lock extraction of direct and transitive dependencies and edges."""
    composer_json = tmp_path / "composer.json"
    composer_json.write_text(json.dumps({
        "name": "nexus/commerce",
        "require": {
            "guzzlehttp/guzzle": "^7.8"
        }
    }))

    composer_lock = tmp_path / "composer.lock"
    composer_lock.write_text(json.dumps({
        "_readme": ["Locks dependencies"],
        "packages": [
            {
                "name": "guzzlehttp/guzzle",
                "version": "7.8.1",
                "require": {
                    "php": "^7.2.5 || ^8.0",
                    "guzzlehttp/psr7": "^1.9 || ^2.4"
                }
            },
            {
                "name": "guzzlehttp/psr7",
                "version": "2.6.2",
                "require": {
                    "php": "^7.2.5 || ^8.0"
                }
            }
        ],
        "packages-dev": [
            {
                "name": "mockery/mockery",
                "version": "1.6.7"
            }
        ]
    }))

    result = parse_composer_lock(str(composer_lock), composer_json_path=str(composer_json))
    assert result.project_name == "nexus/commerce"
    assert result.is_consistent is True

    # Direct package
    assert "guzzlehttp/guzzle" in result.packages
    guzzle = result.packages["guzzlehttp/guzzle"]
    assert guzzle.version == "7.8.1"
    assert guzzle.is_direct is True
    assert guzzle.is_dev is False

    # Transitive package
    assert "guzzlehttp/psr7" in result.packages
    psr7 = result.packages["guzzlehttp/psr7"]
    assert psr7.version == "2.6.2"
    assert psr7.is_direct is False

    # Dev package
    assert "mockery/mockery" in result.packages
    mockery = result.packages["mockery/mockery"]
    assert mockery.is_dev is True

    # Edges
    edge_tuples = [(e["source"], e["target"], e["relation"]) for e in result.dependency_edges]
    # Root -> direct guzzle
    assert any("app:nexus/commerce" in e[0] and "pkg:composer/guzzlehttp/guzzle" in e[1] and e[2] == "depends_on" for e in edge_tuples)
    # guzzle -> transitive psr7
    assert any("pkg:composer/guzzlehttp/guzzle" in e[0] and "pkg:composer/guzzlehttp/psr7" in e[1] and e[2] == "transitive_dependency" for e in edge_tuples)


def test_detect_composer_missing_lock_entry(tmp_path):
    """Verifies detection of packages declared in composer.json but missing from lockfile."""
    composer_json = tmp_path / "composer.json"
    composer_json.write_text(json.dumps({
        "name": "unlocked-app",
        "require": {
            "guzzlehttp/guzzle": "^7.8",
            "aws/aws-sdk-php": "^3.0"
        }
    }))

    composer_lock = tmp_path / "composer.lock"
    composer_lock.write_text(json.dumps({
        "packages": [
            {"name": "guzzlehttp/guzzle", "version": "7.8.1"}
        ]
    }))

    result = parse_composer_lock(str(composer_lock), composer_json_path=str(composer_json))
    assert result.is_consistent is False
    assert any("aws/aws-sdk-php" in inc for inc in result.inconsistencies)


def test_malformed_composer_lock_handled_gracefully(tmp_path):
    """Verifies that malformed JSON in composer.lock returns structured errors without crashing."""
    bad_lock = tmp_path / "composer.lock"
    bad_lock.write_text("{ this is not valid JSON }")

    result = parse_composer_lock(str(bad_lock))
    assert result.is_consistent is False
    assert len(result.inconsistencies) > 0


def test_parse_demo_nexus_commerce_composer():
    """Validates against the actual demo/nexus-commerce/composer files in the repo."""
    res = parse_composer_lock(
        "demo/nexus-commerce/composer.lock",
        composer_json_path="demo/nexus-commerce/composer.json"
    )
    assert res.project_name == "nexus/commerce-backend"
    assert "guzzlehttp/guzzle" in res.packages
    assert res.packages["guzzlehttp/guzzle"].version == "7.8.1"
    assert res.packages["guzzlehttp/guzzle"].is_direct is True


def test_composer_constraint_semantics_unit():
    """Verifies that Composer semver semantics are accurately evaluated."""
    # Composer ~1.2 matches >=1.2 <2.0.0
    ok, _ = check_composer_version_satisfies("1.9.0", "~1.2")
    assert ok is True

    # Composer ~1.2.3 matches >=1.2.3 <1.3.0
    ok, _ = check_composer_version_satisfies("1.2.9", "~1.2.3")
    assert ok is True
    ok, reason = check_composer_version_satisfies("1.3.0", "~1.2.3")
    assert ok is False
    assert "drift:" in reason

    # Caret ^7.8 matches >=7.8.0 <8.0.0
    ok, _ = check_composer_version_satisfies("7.8.1", "^7.8")
    assert ok is True
    ok, reason = check_composer_version_satisfies("8.0.0", "^7.8")
    assert ok is False
    assert "drift:" in reason


def test_composer_lockfile_version_drift(tmp_path):
    """
    Regression test:
    composer.json declares guzzlehttp/guzzle: ^7.8
    composer.lock contains version 6.5.8
    Lockfile must be marked inconsistent.
    """
    composer_json = tmp_path / "composer.json"
    composer_json.write_text(json.dumps({
        "name": "drift-composer-app",
        "require": {
            "guzzlehttp/guzzle": "^7.8"
        }
    }))

    composer_lock = tmp_path / "composer.lock"
    composer_lock.write_text(json.dumps({
        "packages": [
            {"name": "guzzlehttp/guzzle", "version": "6.5.8"}
        ]
    }))

    result = parse_composer_lock(str(composer_lock), composer_json_path=str(composer_json))
    assert result.is_consistent is False
    assert any("guzzlehttp/guzzle" in inc and "mismatch" in inc for inc in result.inconsistencies)


def test_composer_caret_boundary_semantics():
    """
    Regression test for Command A1.3 Requirement 2:
    Composer caret upper-bound calculations and boundary tests:
    - ^0.0.3 = >=0.0.3 <0.0.4
    - ^0.3.0 = >=0.3.0 <0.4.0
    - ^1.2.3 = >=1.2.3 <2.0.0
    Tests immediately below, at, and above each upper bound.
    """
    # 1. ^0.0.3 bounds
    ok_below, _ = check_composer_version_satisfies("0.0.3", "^0.0.3")
    assert ok_below is True

    ok_at, reason = check_composer_version_satisfies("0.0.4", "^0.0.3")
    assert ok_at is False
    assert "drift:" in reason

    ok_above, reason = check_composer_version_satisfies("0.0.5", "^0.0.3")
    assert ok_above is False
    assert "drift:" in reason

    # 2. ^0.3.0 bounds
    ok_below, _ = check_composer_version_satisfies("0.3.9", "^0.3.0")
    assert ok_below is True

    ok_at, reason = check_composer_version_satisfies("0.4.0", "^0.3.0")
    assert ok_at is False
    assert "drift:" in reason

    ok_above, reason = check_composer_version_satisfies("0.4.1", "^0.3.0")
    assert ok_above is False
    assert "drift:" in reason

    # 3. ^1.2.3 bounds
    ok_below, _ = check_composer_version_satisfies("1.99.9", "^1.2.3")
    assert ok_below is True

    ok_at, reason = check_composer_version_satisfies("2.0.0", "^1.2.3")
    assert ok_at is False
    assert "drift:" in reason

    ok_above, reason = check_composer_version_satisfies("2.0.1", "^1.2.3")
    assert ok_above is False
    assert "drift:" in reason


