import logging
from typing import Optional, Dict, Any, List
from app.db import db
from datetime import datetime

logger = logging.getLogger("blindspot.db.repo")

class VendorCertificateRepository:
    @staticmethod
    async def save_certificate(vendor_key: str, pem: str) -> Dict[str, Any]:
        # In-memory storage
        db.in_memory_vendor_certs[vendor_key] = {
            "pem": pem,
            "valid": None,  # to be set after verification
            "created_at": datetime.utcnow().isoformat()
        }
        # Persist to MongoDB if available
        if db.is_connected and db.motor_db is not None:
            try:
                await db.motor_db.vendor_certs.replace_one(
                    {"vendor_key": vendor_key},
                    {"vendor_key": vendor_key, "pem": pem, "valid": None, "created_at": datetime.utcnow()},
                    upsert=True
                )
            except Exception as e:
                logger.error(f"Error persisting vendor certificate {vendor_key}: {e}")
        return db.in_memory_vendor_certs[vendor_key]

    @staticmethod
    async def get_certificate(vendor_key: str) -> Optional[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                rec = await db.motor_db.vendor_certs.find_one({"vendor_key": vendor_key})
                if rec:
                    return rec
            except Exception as e:
                logger.error(f"Error fetching vendor certificate {vendor_key}: {e}")
        return db.in_memory_vendor_certs.get(vendor_key)

    @staticmethod
    async def verify_certificate(vendor_key: str) -> bool:
        # Simple verification placeholder: ensure PEM looks like a certificate
        cert = await VendorCertificateRepository.get_certificate(vendor_key)
        if not cert:
            return False
        pem = cert.get("pem", "")
        is_valid = pem.strip().startswith("-----BEGIN CERTIFICATE-----") and pem.strip().endswith("-----END CERTIFICATE-----")
        cert["valid"] = is_valid
        # Update persistence
        if db.is_connected and db.motor_db is not None:
            try:
                await db.motor_db.vendor_certs.update_one({"vendor_key": vendor_key}, {"$set": {"valid": is_valid}})
            except Exception as e:
                logger.error(f"Error updating cert validity for {vendor_key}: {e}")
        return is_valid

class ScanRepository:

    @staticmethod
    async def save_scan(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = scan_data["scan_id"]
        # Save in memory
        db.in_memory_scans[scan_id] = scan_data

        # Save in MongoDB if active
        if db.is_connected and db.motor_db is not None:
            try:
                await db.motor_db.scans.replace_one(
                    {"scan_id": scan_id},
                    scan_data,
                    upsert=True
                )
            except Exception as e:
                logger.error(f"Error persisting scan {scan_id} to MongoDB: {e}")
        return scan_data

    @staticmethod
    async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                record = await db.motor_db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
                if record:
                    return record
            except Exception as e:
                logger.error(f"Error reading scan {scan_id} from MongoDB: {e}")
        return db.in_memory_scans.get(scan_id)

    @staticmethod
    async def list_scans() -> List[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                cursor = db.motor_db.scans.find({}, {"_id": 0})
                items = await cursor.to_list(length=100)
                if items:
                    return items
            except Exception as e:
                logger.error(f"Error listing scans from MongoDB: {e}")
        return list(db.in_memory_scans.values())

class GraphRepository:
    @staticmethod
    async def save_graph(graph_data: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = graph_data["scan_id"]
        db.in_memory_graphs[scan_id] = graph_data

        if db.is_connected and db.motor_db is not None:
            try:
                await db.motor_db.graphs.replace_one(
                    {"scan_id": scan_id},
                    graph_data,
                    upsert=True
                )
            except Exception as e:
                logger.error(f"Error persisting graph for scan {scan_id} to MongoDB: {e}")
        return graph_data

    @staticmethod
    async def get_graph(scan_id: str) -> Optional[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                record = await db.motor_db.graphs.find_one({"scan_id": scan_id}, {"_id": 0})
                if record:
                    return record
            except Exception as e:
                logger.error(f"Error reading graph for scan {scan_id} from MongoDB: {e}")
        return db.in_memory_graphs.get(scan_id)

class FindingRepository:
    @staticmethod
    async def save_findings(scan_id: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        clean_findings = []
        for f in findings:
            rec = {k: v for k, v in f.items() if k != "_id"}
            rec["scan_id"] = scan_id
            clean_findings.append(rec)
        db.in_memory_findings[scan_id] = clean_findings

        if db.is_connected and db.motor_db is not None and clean_findings:
            try:
                await db.motor_db.findings.delete_many({"scan_id": scan_id})
                await db.motor_db.findings.insert_many(clean_findings)
            except Exception as e:
                logger.error(f"Error persisting findings for scan {scan_id} to MongoDB: {e}")
        return clean_findings

    @staticmethod
    async def get_findings(scan_id: str) -> List[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                cursor = db.motor_db.findings.find({"scan_id": scan_id}, {"_id": 0})
                items = await cursor.to_list(length=500)
                if items:
                    return items
            except Exception as e:
                logger.error(f"Error reading findings for scan {scan_id} from MongoDB: {e}")
        return db.in_memory_findings.get(scan_id, [])

class ScenarioRepository:
    @staticmethod
    async def save_scenario(scenario_data: Dict[str, Any]) -> Dict[str, Any]:
        scenario_id = scenario_data["scenario_id"]
        scan_id = scenario_data["scan_id"]
        if scan_id not in db.in_memory_scenarios:
            db.in_memory_scenarios[scan_id] = []
        # Update or append in memory
        db.in_memory_scenarios[scan_id] = [
            s for s in db.in_memory_scenarios[scan_id] if s.get("scenario_id") != scenario_id
        ] + [scenario_data]

        if db.is_connected and db.motor_db is not None:
            try:
                await db.motor_db.scenarios.replace_one(
                    {"scenario_id": scenario_id},
                    scenario_data,
                    upsert=True
                )
            except Exception as e:
                logger.error(f"Error persisting scenario {scenario_id} to MongoDB: {e}")
        return scenario_data

    @staticmethod
    async def get_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                record = await db.motor_db.scenarios.find_one({"scenario_id": scenario_id}, {"_id": 0})
                if record:
                    return record
            except Exception as e:
                logger.error(f"Error reading scenario {scenario_id} from MongoDB: {e}")

        for sc_list in db.in_memory_scenarios.values():
            for item in sc_list:
                if item.get("scenario_id") == scenario_id:
                    return item
        return None

class EvidenceRepository:
    @staticmethod
    async def save_evidence(scan_id: str, evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        db.in_memory_evidence[scan_id] = evidence_list
        if db.is_connected and db.motor_db is not None and evidence_list:
            try:
                await db.motor_db.evidence.delete_many({"scan_id": scan_id})
                clean_records = []
                for ev in evidence_list:
                    rec = {k: v for k, v in ev.items() if k != "_id"}
                    rec["scan_id"] = scan_id
                    clean_records.append(rec)
                await db.motor_db.evidence.insert_many(clean_records)
            except Exception as e:
                logger.error(f"Error persisting evidence for scan {scan_id} to MongoDB: {e}")
        return evidence_list

    @staticmethod
    async def get_evidence(scan_id: str) -> List[Dict[str, Any]]:
        if db.is_connected and db.motor_db is not None:
            try:
                cursor = db.motor_db.evidence.find({"scan_id": scan_id}, {"_id": 0})
                items = await cursor.to_list(length=500)
                if items:
                    return items
            except Exception as e:
                logger.error(f"Error reading evidence for scan {scan_id} from MongoDB: {e}")
        return db.in_memory_evidence.get(scan_id, [])
