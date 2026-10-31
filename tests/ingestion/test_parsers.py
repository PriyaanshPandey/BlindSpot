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
    assert findings[0]["cve"] == "CVE-2018-3721"

