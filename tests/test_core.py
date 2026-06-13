import pytest
import os
import json
from agent_shield.contracts import shield, ShieldViolationError

def test_forbidden_import_raises_error():
    """Verifies that importing a forbidden module triggers ShieldViolationError at definition time."""
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield(forbidden_imports=["sys"])
        def function_with_forbidden_import():
            import sys
            return {}
            
    assert "contains forbidden imports: sys" in str(exc_info.value)
    
    # Verify the JSON report was generated
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "forbidden_import"
    assert report["function_name"] == "function_with_forbidden_import"
    assert "sys" in report["forbidden_imports"]


def test_return_type_mismatch_raises_error():
    """Verifies that returning an incorrect type raises ShieldViolationError at runtime."""
    @shield
    def function_with_type_mismatch() -> dict:
        return "not-a-dict"  # type: ignore
        
    with pytest.raises(ShieldViolationError) as exc_info:
        function_with_type_mismatch()
        
    assert "returned type 'str' instead of expected 'dict'" in str(exc_info.value)

    # Verify the JSON report was generated
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "return_type_mismatch"
    assert report["function_name"] == "function_with_type_mismatch"
    assert report["expected_type"] == "dict"
    assert report["actual_type"] == "str"


def test_successful_contract():
    """Verifies that a function obeying all boundaries executes successfully."""
    @shield(forbidden_imports=["sys"])
    def valid_function(x: int) -> int:
        import os  # 'os' is allowed since only 'sys' is forbidden
        return x + 1
        
    assert valid_function(5) == 6


def test_dummy_app_import_raises_error():
    """Verifies that importing the dummy app raises ShieldViolationError due to its definition-time check."""
    import sys
    # Clear from sys.modules to ensure it executes the definition-time code on import
    sys.modules.pop("tests.dummy_app", None)
    
    with pytest.raises(ShieldViolationError) as exc_info:
        import tests.dummy_app  # type: ignore
        
    assert "Function 'process_payment' contains forbidden imports: os" in str(exc_info.value)

