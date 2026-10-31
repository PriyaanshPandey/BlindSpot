"""
HDX Test Runner: Executes all backend test suites and validates functionality.
"""
import sys
import os

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, backend_dir)
sys.path.insert(0, root_dir)

import traceback

def run_suite():
    passed = 0
    failed = 0
    errors = []

    print("=" * 60)
    print(" Hidden Dependency X-Ray (HDX) - Backend Test Runner ")
    print("=" * 60)

    # 1. Test Graph Engine
    try:
        from tests.graph.test_graph_engine import (
            test_blast_radius_computation,
            test_find_dependency_chains,
            test_isolated_nodes,
            test_graph_filtering_layers
        )
        test_blast_radius_computation()
        print(" [PASS] test_blast_radius_computation")
        test_find_dependency_chains()
        print(" [PASS] test_find_dependency_chains")
        test_isolated_nodes()
        print(" [PASS] test_isolated_nodes")
        test_graph_filtering_layers()
        print(" [PASS] test_graph_filtering_layers")
        passed += 4
    except Exception as e:
        failed += 1
        errors.append(("GraphEngine", e, traceback.format_exc()))
        print(f" [FAIL] GraphEngine: {e}")

    # 2. Test Simulation Engine
    try:
        from tests.test_simulation import test_failure_simulation_financial_calculation
        test_failure_simulation_financial_calculation()
        print(" [PASS] test_failure_simulation_financial_calculation")
        passed += 1
    except Exception as e:
        failed += 1
        errors.append(("Simulation", e, traceback.format_exc()))
        print(f" [FAIL] Simulation: {e}")

    # 3. Test Reconciliation & Discrepancies
    try:
        from tests.test_reconciliation import test_reconciliation_and_discrepancy_detection
        test_reconciliation_and_discrepancy_detection()
        print(" [PASS] test_reconciliation_and_discrepancy_detection")
        passed += 1
    except Exception as e:
        failed += 1
        errors.append(("Reconciliation", e, traceback.format_exc()))
        print(f" [FAIL] Reconciliation: {e}")

    # 4. Test Ingestion Parsers
    try:
        from tests.ingestion.test_parsers import test_check_vulnerabilities
        test_check_vulnerabilities()
        print(" [PASS] test_check_vulnerabilities (Role A)")
        passed += 1
    except Exception as e:
        failed += 1
        errors.append(("Ingestion", e, traceback.format_exc()))
        print(f" [FAIL] Ingestion: {e}")

    # 5. Test Full API Routes
    try:
        from tests.api.test_routes import test_health_endpoint, test_full_scan_graph_simulation_lifecycle
        test_health_endpoint()
        print(" [PASS] test_health_endpoint")
        test_full_scan_graph_simulation_lifecycle()
        print(" [PASS] test_full_scan_graph_simulation_lifecycle")
        passed += 2
    except Exception as e:
        failed += 1
        errors.append(("API Routes", e, traceback.format_exc()))
        print(f" [FAIL] API Routes: {e}")

    print("=" * 60)
    print(f" Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)

    if errors:
        print("\nFailures:")
        for name, err, tb in errors:
            print(f"\n--- {name} ---")
            print(tb)
        sys.exit(1)
    else:
        print("\nAll Core Backend tests passed successfully!")
        sys.exit(0)

if __name__ == "__main__":
    run_suite()
