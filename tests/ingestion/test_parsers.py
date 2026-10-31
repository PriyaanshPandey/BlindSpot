import pytest
from app.ingestion import parse_package_json
from app.security import check_vulnerabilities

def test_parse_package_json(tmp_path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"name": "test-app", "dependencies": {"express": "^4.19.0"}}')
    res = parse_package_json(str(pkg_file))
    assert res["name"] == "test-app"
    assert "express" in res["dependencies"]

def test_check_vulnerabilities():
    deps = {"event-stream": "3.3.6"}
    findings = check_vulnerabilities(deps)
    assert len(findings) == 1
    assert findings[0]["advisory_id"] == "GHSA-mh6f-8j2x-4483"
    assert findings[0]["cve"] is None
    assert findings[0]["malicious_dependency"] == "flatmap-stream"
    assert findings[0]["fixed_version"] == "4.0.0"
    assert findings[0]["classification"] == "vulnerability_compromised_package"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["execution_proof"] is False

