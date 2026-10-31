"""
Unit tests for Security Vulnerability and Compromised Package Detection [Role A].
Ensures correct mapping of event-stream to GHSA-mh6f-8j2x-4483, rejection of fabricated CVEs,
and clear distinction between static presence and executed compromise.
"""

import pytest
from app.security import check_vulnerabilities, CURATED_ADVISORIES


def test_event_stream_compromised_package_advisory():
    """Verifies that event-stream@3.3.6 maps to GHSA-mh6f-8j2x-4483 with no CVE fabricated."""
    deps = {"event-stream": "3.3.6"}
    findings = check_vulnerabilities(deps)

    assert len(findings) == 1
    f = findings[0]
    assert f["package"] == "event-stream"
    assert f["version"] == "3.3.6"
    assert f["ecosystem"] == "npm"
    assert f["advisory_id"] == "GHSA-mh6f-8j2x-4483"
    assert f["cve"] is None  # Must NOT fabricate CVE-2018-3721
    assert f["malicious_dependency"] == "flatmap-stream"
    assert f["fixed_version"] == "4.0.0"
    assert f["classification"] == "vulnerability_compromised_package"
    assert f["severity"] == "critical"
    # Execution status distinction
    assert f["execution_status"] == "presence_detected_unexecuted"
    assert f["execution_proof"] is False


def test_clean_version_with_semver_prefix():
    """Verifies that versions with semver ranges (^ or ~) are cleaned before advisory matching."""
    deps = {"event-stream": "^3.3.6"}
    findings = check_vulnerabilities(deps)
    assert len(findings) == 1
    assert findings[0]["version"] == "3.3.6"


def test_non_vulnerable_version_no_finding():
    """Verifies that non-compromised versions (e.g. 4.0.0 or 3.3.4) do not trigger false alarms."""
    deps = {"event-stream": "4.0.0", "lodash": "4.17.21"}
    findings = check_vulnerabilities(deps)
    assert len(findings) == 0


def test_jsonwebtoken_known_cve():
    """
    Verifies that GHSA-hjrf-2m68-5959 maps to CVE-2022-23541 with medium severity,
    patched version 9.0.0, and is NOT associated with CVE-2022-23529.
    """
    deps = {"jsonwebtoken": "8.5.1"}
    findings = check_vulnerabilities(deps)
    assert len(findings) == 1
    f = findings[0]
    assert f["advisory_id"] == "GHSA-hjrf-2m68-5959"
    assert f["cve"] == "CVE-2022-23541"
    assert f["cve"] != "CVE-2022-23529"
    assert f["severity"] == "medium"
    assert f["fixed_version"] == "9.0.0"
    assert f["classification"] == "vulnerability_known_cve"
    assert f["execution_status"] == "presence_detected_unexecuted"
    assert f["execution_proof"] is False


def test_version_range_matching_850_851_900():
    """
    Verifies affected range <=8.5.1 matches 8.5.0 and 8.5.1,
    while patched version 9.0.0 produces no vulnerability findings.
    """
    # 8.5.0 is vulnerable
    res_850 = check_vulnerabilities([{"name": "jsonwebtoken", "version": "8.5.0"}])
    assert len(res_850) == 1
    assert res_850[0]["cve"] == "CVE-2022-23541"
    assert res_850[0]["severity"] == "medium"

    # 8.5.1 is vulnerable
    res_851 = check_vulnerabilities([{"name": "jsonwebtoken", "version": "8.5.1"}])
    assert len(res_851) == 1
    assert res_851[0]["cve"] == "CVE-2022-23541"
    assert res_851[0]["severity"] == "medium"

    # 9.0.0 is patched / not vulnerable
    res_900 = check_vulnerabilities([{"name": "jsonwebtoken", "version": "9.0.0"}])
    assert len(res_900) == 0


def test_multiple_installed_versions_evaluated_independently():
    """
    Verifies that multiple installed versions of the same package at different paths
    are evaluated independently and never collapsed into a single mapping.
    """
    packages = [
        {"name": "jsonwebtoken", "version": "8.5.1", "path": "node_modules/legacy/node_modules/jsonwebtoken"},
        {"name": "jsonwebtoken", "version": "9.0.0", "path": "node_modules/jsonwebtoken"},
    ]
    findings = check_vulnerabilities(packages, ecosystem="npm")
    assert len(findings) == 1
    assert findings[0]["version"] == "8.5.1"
    assert findings[0]["path"] == "node_modules/legacy/node_modules/jsonwebtoken"
    assert findings[0]["cve"] == "CVE-2022-23541"


def test_flatmap_stream_flagged_as_compromised():
    """
    Verifies that flatmap-stream is flagged as a compromised package
    associated with the event-stream incident, preserving execution distinction.
    """
    deps = {"flatmap-stream": "0.1.1"}
    findings = check_vulnerabilities(deps, ecosystem="npm")
    assert len(findings) == 1
    f = findings[0]
    assert f["package"] == "flatmap-stream"
    assert f["advisory_id"] == "GHSA-mh6f-8j2x-4483"
    assert f["cve"] is None
    assert f["severity"] == "critical"
    assert f["classification"] == "vulnerability_compromised_package"
    assert f["execution_status"] == "presence_detected_unexecuted"
    assert f["execution_proof"] is False


def test_ecosystem_filtering():
    """Verifies that the supplied ecosystem argument is strictly respected."""
    # npm package searched under composer ecosystem should yield no findings
    findings = check_vulnerabilities(
        [{"name": "jsonwebtoken", "version": "8.5.1"}],
        ecosystem="composer"
    )
    assert len(findings) == 0

    # npm package searched under npm ecosystem yields finding
    findings_npm = check_vulnerabilities(
        [{"name": "jsonwebtoken", "version": "8.5.1"}],
        ecosystem="npm"
    )
    assert len(findings_npm) == 1


def test_flatmap_stream_covers_all_versions_and_distinguishes_ghsa_9x64_5r7x():
    """
    Regression test for Command A1.4 Requirement 1:
    - Covers versions 0.1.0, 0.1.1, 0.1.2, 0.1.3, 1.0.0 under broader compromised package advisory GHSA-mh6f-8j2x-4483.
    - Exact advisory ID GHSA-9x64-5r7x-2q53 is returned ONLY for version 0.1.1 when prefer_exact_advisory=True.
    - Other versions (0.1.0, 0.1.2, 0.1.3, 1.0.0) return the broader GHSA-mh6f-8j2x-4483 advisory even when prefer_exact_advisory=True.
    - No patched version is invented (fixed_version=None).
    - Maintains the recommendation to remove flatmap-stream completely across all versions.
    """
    test_versions = ["0.1.0", "0.1.1", "0.1.2", "0.1.3", "1.0.0"]

    for ver in test_versions:
        # Default advisory mode
        res = check_vulnerabilities([{"name": "flatmap-stream", "version": ver}], ecosystem="npm")
        assert len(res) == 1, f"Expected finding for flatmap-stream@{ver}"
        f = res[0]
        assert f["package"] == "flatmap-stream"
        assert f["version"] == ver
        assert f["advisory_id"] == "GHSA-mh6f-8j2x-4483"
        assert f["fixed_version"] is None
        assert "remove" in f["remediation"]["summary"].lower()

        # prefer_exact_advisory mode
        res_exact = check_vulnerabilities(
            [{"name": "flatmap-stream", "version": ver}],
            ecosystem="npm",
            prefer_exact_advisory=True
        )
        assert len(res_exact) == 1, f"Expected finding for flatmap-stream@{ver} with prefer_exact_advisory"
        f_exact = res_exact[0]
        assert f_exact["package"] == "flatmap-stream"
        assert f_exact["version"] == ver
        assert f_exact["fixed_version"] is None
        assert "remove" in f_exact["remediation"]["summary"].lower()

        if ver == "0.1.1":
            assert f_exact["advisory_id"] == "GHSA-9x64-5r7x-2q53"
            assert f_exact["exact_advisory_id"] == "GHSA-9x64-5r7x-2q53"
            assert "GHSA-9x64-5r7x-2q53" in f_exact["related_advisories"]
        else:
            assert f_exact["advisory_id"] == "GHSA-mh6f-8j2x-4483"
            assert f_exact["exact_advisory_id"] is None


