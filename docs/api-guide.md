# HDX API Integration Guide

Base URL: `http://localhost:8000/api/v1`

## 1. System Health
```bash
curl -X GET "http://localhost:8000/api/v1/health"
```

## 2. Trigger Scan
```bash
curl -X POST "http://localhost:8000/api/v1/scans" \
     -H "Content-Type: application/json" \
     -d '{
       "repo_path": "./demo/nexus-commerce",
       "trace_file_path": "./fixtures/runtime/traces.sample.json",
       "enable_vendor_passports": true
     }'
```

## 3. Retrieve Unified Graph
```bash
curl -X GET "http://localhost:8000/api/v1/scans/{scan_id}/graph?filter_layer=all"
```

## 4. Run Failure Simulation
```bash
curl -X POST "http://localhost:8000/api/v1/scans/{scan_id}/simulate" \
     -H "Content-Type: application/json" \
     -d '{
       "target_node_id": "vendor:stripe",
       "failure_duration_hours": 4.0,
       "failure_type": "complete_outage"
     }'
```

## 5. Fetch Verified Knowledge Bundle
```bash
curl -X GET "http://localhost:8000/api/v1/knowledge/bundle"
```

