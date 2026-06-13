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


def test_eval_blocked_by_default():
    """Verifies that a function using eval() wrapped with a standard @shield() raises ShieldViolationError."""
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_eval():
            eval("1 + 1")
    assert "contains calls to dangerous functions: eval" in str(exc_info.value)


def test_exec_blocked_by_default():
    """Verifies that a function using exec() wrapped with a standard @shield() raises ShieldViolationError."""
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_exec():
            exec("x = 1")
    assert "contains calls to dangerous functions: exec" in str(exc_info.value)


def test_unsafe_allowed_with_flag():
    """Verifies that if a function uses eval() but is decorated with allow_unsafe=True, it runs without error."""
    @shield(allow_unsafe=True)
    def func_allowed_eval():
        eval("1 + 1")
        return 42
    assert func_allowed_eval() == 42


def test_global_blocked_by_default():
    """Verifies that using global keyword inside a function with @shield() raises ShieldViolationError."""
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_global():
            global my_global_var
            my_global_var = 1
    assert "modifies global state using the 'global' keyword" in str(exc_info.value)


def test_global_allowed_with_flag():
    """Verifies that a function using global with @shield(allow_globals=True) executes successfully."""
    @shield(allow_globals=True)
    def func_allowed_global():
        global another_global_var
        another_global_var = 100
        return another_global_var
    assert func_allowed_global() == 100


def test_detect_hardcoded_secrets():
    from agent_shield.inspector import detect_hardcoded_secrets

    def func_with_openai_key():
        key = "sk-proj-1234567890abcdef1234567890abcdef123456"
        return key

    def func_with_aws_key():
        aws_id = "AKIA1234567890ABCDEF"
        return aws_id

    def func_with_suspicious_var():
        api_key = "my_super_secret_api_token"
        return api_key

    def func_with_bearer():
        auth = "Bearer abcdef1234567890"
        return auth

    def func_clean():
        placeholder_key = "TODO"
        generic_string = "hello world"
        return generic_string

    assert "sk-proj-1234567890abcdef1234567890abcdef123456" in detect_hardcoded_secrets(func_with_openai_key)
    assert "AKIA1234567890ABCDEF" in detect_hardcoded_secrets(func_with_aws_key)
    assert "my_super_secret_api_token" in detect_hardcoded_secrets(func_with_suspicious_var)
    assert "Bearer abcdef1234567890" in detect_hardcoded_secrets(func_with_bearer)
    assert detect_hardcoded_secrets(func_clean) == []


def test_detect_cpu_lockups():
    from agent_shield.inspector import detect_cpu_lockups

    def func_with_while_true_pass():
        while True:
            pass

    def func_with_while_true_literal():
        while 1:
            "idle string"

    def func_clean_while():
        x = 0
        while x < 10:
            x += 1
        return x

    assert detect_cpu_lockups(func_with_while_true_pass) is True
    assert detect_cpu_lockups(func_with_while_true_literal) is True
    assert detect_cpu_lockups(func_clean_while) is False





