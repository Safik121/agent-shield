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
    assert "sys" in report["details"]["forbidden_imports"]


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


def test_detect_dangerous_functions():
    from agent_shield.inspector import detect_dangerous_functions
    
    def func_with_eval():
        eval("1 + 1")
        
    def func_with_exec():
        exec("x = 1")
        
    def func_with_both():
        eval("1")
        exec("y = 2")
        
    def func_clean():
        return 42
        
    assert detect_dangerous_functions(func_with_eval) == ["eval"]
    assert detect_dangerous_functions(func_with_exec) == ["exec"]
    assert detect_dangerous_functions(func_with_both) == ["eval", "exec"]
    assert detect_dangerous_functions(func_clean) == []


def test_detect_global_keyword():
    from agent_shield.inspector import detect_global_keyword
    
    def func_with_global():
        global val
        val = 1
        
    def func_clean():
        val = 1
        return val
        
    assert detect_global_keyword(func_with_global) is True
    assert detect_global_keyword(func_clean) is False


def test_shield_detects_dangerous_execution():
    # Test that eval/exec triggers violation by default
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()  # allow_unsafe=False by default
        def func_with_eval():
            eval("1 + 1")
    assert "contains calls to dangerous functions: eval" in str(exc_info.value)

    # Verify JSON report structure
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "dangerous_execution"
    assert "eval" in report["details"]["dangerous_functions"]

    # Test that allow_unsafe=True bypasses the check
    @shield(allow_unsafe=True)
    def func_allowed_eval():
        eval("1 + 1")
        return 42
    assert func_allowed_eval() == 42


def test_shield_detects_global_scope():
    # Test that global keyword triggers violation by default
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()  # allow_globals=False by default
        def func_with_global():
            global my_global_var
            my_global_var = 1
    assert "modifies global state using the 'global' keyword" in str(exc_info.value)

    # Verify JSON report structure
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "global_scope_violation"
    assert report["details"]["global_keyword_detected"] is True

    # Test that allow_globals=True bypasses the check
    @shield(allow_globals=True)
    def func_allowed_global():
        global another_global_var
        another_global_var = 100
        return another_global_var
    assert func_allowed_global() == 100



