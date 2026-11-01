import pytest
import os
import asyncio
from datetime import datetime
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from app.core.config import settings
from app.db import db
from app.db.repositories import (
    ScanRepository,
    GraphRepository,
    FindingRepository,
    ScenarioRepository,
    EvidenceRepository
)
from app.api.routes.scans import create_scan, get_scan
from app.api.routes.graph import get_scan_graph, get_scan_findings, get_scan_evidence
from app.api.routes.scenarios import simulate_failure, get_scenario
from app.models import ScanRequest, SimulationRequest

TEST_MONGO_URI = "mongodb://127.0.0.1:27017"
TEST_DB_NAME = "blindspot_test"

@pytest.mark.asyncio
async def test_live_mongodb_connection_and_persistence():
    try:
        # 1. Connect to isolated test database
        await db.connect(uri=TEST_MONGO_URI, db_name=TEST_DB_NAME)
        if not db.is_connected:
            print("MongoDB service not active on 127.0.0.1:27017 - skipping live MongoDB tests")
            return
        assert db.is_connected is True
        assert db.storage_mode == "mongodb"
        assert db.motor_db is not None
        assert db.db_name == TEST_DB_NAME

        # 2. Inspect actual MongoDB index definitions directly
        findings_indexes = await db.motor_db.findings.index_information()
        evidence_indexes = await db.motor_db.evidence.index_information()

        # Confirm unique compound index (scan_id, id) in findings
        findings_compound = any(
            idx.get("key") == [("scan_id", 1), ("id", 1)] and idx.get("unique") is True
            for idx in findings_indexes.values()
        )
        assert findings_compound, f"Findings missing unique compound index (scan_id, id). Found: {findings_indexes}"

        # Confirm no remaining global unique index on id in findings
        findings_global_id = any(
            idx.get("key") == [("id", 1)] and idx.get("unique") is True
            for idx in findings_indexes.values()
        )
        assert not findings_global_id, f"Findings has prohibited global unique index on id. Found: {findings_indexes}"

        # Confirm unique compound index (scan_id, id) in evidence
        evidence_compound = any(
            idx.get("key") == [("scan_id", 1), ("id", 1)] and idx.get("unique") is True
            for idx in evidence_indexes.values()
        )
        assert evidence_compound, f"Evidence missing unique compound index (scan_id, id). Found: {evidence_indexes}"

        # Confirm no remaining global unique index on id in evidence
        evidence_global_id = any(
            idx.get("key") == [("id", 1)] and idx.get("unique") is True
            for idx in evidence_indexes.values()
        )
        assert not evidence_global_id, f"Evidence has prohibited global unique index on id. Found: {evidence_indexes}"

        # 3. Trigger first scan on demo project
        demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test-projects", "nexus-commerce"))
        trace_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "runtime", "traces.sample.json"))

        scan_req = ScanRequest(
            repo_path=demo_path,
            trace_file_path=trace_path,
            enable_vendor_passports=True
        )

        scan_res_1 = await create_scan(scan_req)
        scan_id_1 = scan_res_1["scan_id"]
        assert scan_res_1["status"] == "completed"

        # 4. Trigger second complete scan of the same demo project to verify duplicate-ID handling
        scan_res_2 = await create_scan(scan_req)
        scan_id_2 = scan_res_2["scan_id"]
        assert scan_res_2["status"] == "completed"
        assert scan_id_1 != scan_id_2, "Two sequential scans must generate distinct scan IDs"

        # 5. Verify records for BOTH scans independently
        for s_id in (scan_id_1, scan_id_2):
            # Scan record exists
            s_doc = await db.motor_db.scans.find_one({"scan_id": s_id}, {"_id": 0})
            assert s_doc is not None, f"Scan {s_id} not found in MongoDB"
            assert s_doc["scan_id"] == s_id
            assert s_doc["project_name"] == "nexus-commerce"

            # Graph exists and contains nodes and edges
            g_doc = await db.motor_db.graphs.find_one({"scan_id": s_id}, {"_id": 0})
            assert g_doc is not None, f"Graph for scan {s_id} not found in MongoDB"
            assert g_doc["scan_id"] == s_id
            assert len(g_doc["nodes"]) > 0, f"Graph for scan {s_id} has no nodes"
            assert len(g_doc["edges"]) > 0, f"Graph for scan {s_id} has no edges"

            # Findings are persisted
            f_list = await db.motor_db.findings.find({"scan_id": s_id}, {"_id": 0}).to_list(200)
            assert len(f_list) > 0, f"No findings persisted for scan {s_id}"
            assert all(f.get("scan_id") == s_id for f in f_list)

            # Evidence is persisted
            e_list = await db.motor_db.evidence.find({"scan_id": s_id}, {"_id": 0}).to_list(200)
            assert len(e_list) > 0, f"No evidence persisted for scan {s_id}"
            assert all(e.get("scan_id") == s_id for e in e_list)

        # 6. Verify duplicate-ID behavior across the two scans
        findings_1 = await db.motor_db.findings.find({"scan_id": scan_id_1}, {"_id": 0}).to_list(200)
        findings_2 = await db.motor_db.findings.find({"scan_id": scan_id_2}, {"_id": 0}).to_list(200)
        evidence_1 = await db.motor_db.evidence.find({"scan_id": scan_id_1}, {"_id": 0}).to_list(200)
        evidence_2 = await db.motor_db.evidence.find({"scan_id": scan_id_2}, {"_id": 0}).to_list(200)

        finding_ids_1 = {f["id"] for f in findings_1}
        finding_ids_2 = {f["id"] for f in findings_2}
        common_finding_ids = finding_ids_1.intersection(finding_ids_2)
        assert len(common_finding_ids) > 0, "Expected finding IDs to repeat across scans of the same demo project"

        evidence_ids_1 = {e["id"] for e in evidence_1}
        evidence_ids_2 = {e["id"] for e in evidence_2}
        common_evidence_ids = evidence_ids_1.intersection(evidence_ids_2)
        assert len(common_evidence_ids) > 0, "Expected evidence IDs to repeat across scans of the same demo project"

        # 7. Verify both scans independently retrieve their own records via repositories
        retrieved_f1 = await FindingRepository.get_findings(scan_id_1)
        retrieved_f2 = await FindingRepository.get_findings(scan_id_2)
        assert len(retrieved_f1) == len(findings_1)
        assert len(retrieved_f2) == len(findings_2)
        assert all(f.get("scan_id") == scan_id_1 for f in retrieved_f1)
        assert all(f.get("scan_id") == scan_id_2 for f in retrieved_f2)

        retrieved_e1 = await EvidenceRepository.get_evidence(scan_id_1)
        retrieved_e2 = await EvidenceRepository.get_evidence(scan_id_2)
        assert len(retrieved_e1) == len(evidence_1)
        assert len(retrieved_e2) == len(evidence_2)
        assert all(e.get("scan_id") == scan_id_1 for e in retrieved_e1)
        assert all(e.get("scan_id") == scan_id_2 for e in retrieved_e2)

        # 8. Run Failure Simulation on scan_id_1 and verify persistence
        sim_req = SimulationRequest(
            target_node_id="vendor:stripe",
            failure_type="complete_outage",
            failure_duration_hours=4.0,
            hourly_transactions_override=1200.0,
            average_transaction_value_override=45.0
        )
        sim_res = await simulate_failure(scan_id_1, sim_req)
        scenario_id = sim_res["scenario_id"]

        mongo_scen = await db.motor_db.scenarios.find_one({"scenario_id": scenario_id}, {"_id": 0})
        assert mongo_scen is not None
        assert mongo_scen["scenario_id"] == scenario_id
        assert mongo_scen["impact_results"]["total_estimated_gross_exposure"] == 216000.0

        # 9. Test persistence across simulated restart (close, wipe in-memory, reconnect)
        await db.close()
        assert db.is_connected is False

        db.in_memory_scans.clear()
        db.in_memory_graphs.clear()
        db.in_memory_findings.clear()
        db.in_memory_scenarios.clear()
        db.in_memory_evidence.clear()

        # Reconnect to isolated test database
        await db.connect(uri=TEST_MONGO_URI, db_name=TEST_DB_NAME)
        assert db.is_connected is True

        reloaded_scan = await ScanRepository.get_scan(scan_id_1)
        assert reloaded_scan is not None
        assert reloaded_scan["scan_id"] == scan_id_1

        reloaded_graph = await GraphRepository.get_graph(scan_id_1)
        assert reloaded_graph is not None
        assert reloaded_graph["scan_id"] == scan_id_1

        reloaded_findings = await FindingRepository.get_findings(scan_id_1)
        assert len(reloaded_findings) == len(findings_1)
        assert all(f.get("scan_id") == scan_id_1 for f in reloaded_findings)

        # Verify evidence reloaded from MongoDB after reconnecting
        reloaded_evidence = await EvidenceRepository.get_evidence(scan_id_1)
        assert reloaded_evidence is not None
        assert len(reloaded_evidence) == len(evidence_1)
        assert all(e.get("scan_id") == scan_id_1 for e in reloaded_evidence)
        assert {e["id"] for e in reloaded_evidence} == {e["id"] for e in evidence_1}

        # Verify failure scenario reloaded from MongoDB after reconnecting
        reloaded_scenario = await ScenarioRepository.get_scenario(scenario_id)
        assert reloaded_scenario is not None
        assert reloaded_scenario["scenario_id"] == scenario_id
        assert reloaded_scenario["scan_id"] == scan_id_1
        assert reloaded_scenario["impact_results"]["total_estimated_gross_exposure"] == 216000.0

        # Verify duplicate finding ID within the same scan is rejected by compound unique index
        sample_finding = findings_1[0]
        duplicate_finding = {
            "id": sample_finding["id"],
            "scan_id": scan_id_1,
            "type": "vulnerability_compromised_package",
            "title": "Duplicate Key Test Finding"
        }
        duplicate_rejected = False
        try:
            await db.motor_db.findings.insert_one(duplicate_finding)
        except DuplicateKeyError:
            duplicate_rejected = True
        assert duplicate_rejected is True, (
            f"Expected DuplicateKeyError for duplicate (scan_id={scan_id_1}, id={sample_finding['id']})"
        )

        # 10. Test that unknown scan IDs return 404
        try:
            await get_scan_graph("unknown-scan-uuid-1234")
            assert False, "Should have raised 404"
        except HTTPException as e:
            assert e.status_code == 404

        try:
            await get_scan_findings("unknown-scan-uuid-1234")
            assert False, "Should have raised 404"
        except HTTPException as e:
            assert e.status_code == 404

        print("MongoDB live integration tests: ALL PASSED!")

    finally:
        # Cleanup: Remove test data only from blindspot_test; NEVER touch blindspot!
        if db.client is not None:
            try:
                await db.client.drop_database(TEST_DB_NAME)
            except Exception:
                pass
        await db.close()
        # Reset in-memory storage to clean state
        db.in_memory_scans.clear()
        db.in_memory_graphs.clear()
        db.in_memory_findings.clear()
        db.in_memory_scenarios.clear()
        db.in_memory_evidence.clear()

if __name__ == "__main__":
    asyncio.run(test_live_mongodb_connection_and_persistence())
