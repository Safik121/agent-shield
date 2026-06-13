import pytest
import os
import json
from agent_shield.contracts import shield, ShieldViolationError
from agent_shield.sandbox import mock_only

@mock_only
def module_level_mock_only_func():
    return "real-execution"


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


def test_shield_detects_hardcoded_secrets():
    # Test that @shield automatically checks for secrets
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_secret():
            api_key = "my_secret_token_12345"
            return api_key
    assert "contains hardcoded secrets: my_secret_token_12345" in str(exc_info.value)

    # Verify JSON report structure
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "hardcoded_secret"
    assert "my_secret_token_12345" in report["details"]["hardcoded_secrets"]


def test_shield_detects_cpu_lockups():
    # Test that @shield automatically checks for cpu lockups
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_lockup():
            while True:
                pass
    assert "contains a potential infinite loop causing a CPU lockup" in str(exc_info.value)

    # Verify JSON report structure
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "cpu_lockup_hazard"
    assert report["details"]["cpu_lockup_detected"] is True


def test_hardcoded_secret_blocked():
    """Verifies that a function containing a hardcoded secret raises ShieldViolationError."""
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_secret():
            password = "my_secret_token"
            return password
    assert "contains hardcoded secrets: my_secret_token" in str(exc_info.value)


def test_cpu_lockup_blocked():
    """Verifies that a function containing an empty while True loop raises ShieldViolationError."""
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield()
        def func_with_lockup():
            while True:
                pass
    assert "contains a potential infinite loop causing a CPU lockup" in str(exc_info.value)


def test_enterprise_flags_allow_execution():
    """Verifies that allow_unsafe=True and allow_globals=True flags permit eval and global usage."""
    @shield(allow_unsafe=True, allow_globals=True)
    def allowed_enterprise_func() -> dict:
        global enterprise_state
        enterprise_state = "active"
        eval("1 + 1")
        return {"status": "ok"}

    assert allowed_enterprise_func() == {"status": "ok"}


def test_frozen_function_tamper_detection():
    """Verifies that @freeze registers a function hash and blocks modifications with ShieldViolationError."""
    from agent_shield.freezer import freeze

    # 1. Clean the key from lockfile if it exists
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lockfile_path = os.path.join(project_root, "shield_reports", "frozen_functions.json")
    
    if os.path.exists(lockfile_path):
        try:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                data = json.loads(content) if content else {}
        except Exception:
            data = {}
        data.pop("my_frozen_function", None)
        with open(lockfile_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
    # 2. Define a function and freeze it
    @freeze
    def my_frozen_function():
        return "original"
        
    # Check that it is registered
    assert os.path.exists(lockfile_path)
    with open(lockfile_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "my_frozen_function" in data
    
    # 3. Modify the hash in the lockfile to simulate an unauthorized change
    data["my_frozen_function"] = "fake-different-hash"
    with open(lockfile_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    # 4. Try defining the function again and verify it raises ShieldViolationError
    with pytest.raises(ShieldViolationError) as exc_info:
        @freeze
        def my_frozen_function():
            return "original"
            
    assert "Function 'my_frozen_function' is frozen by the architect and cannot be modified" in str(exc_info.value)
    
    # Cleanup
    with open(lockfile_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.pop("my_frozen_function", None)
    with open(lockfile_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def test_package_exports():
    """Verifies that the package root exports shield, ShieldViolationError, freeze, prompt_inject, lock_signature, mock_only, timeout, limit_memory, restrict_network, prompt_assert, init_config, restrict_fs, FilesystemViolationError, no_side_effects, SideEffectViolationError, and ComplexityViolationError."""
    import agent_shield
    assert hasattr(agent_shield, "shield")
    assert hasattr(agent_shield, "ShieldViolationError")
    assert hasattr(agent_shield, "freeze")
    assert hasattr(agent_shield, "prompt_inject")
    assert hasattr(agent_shield, "lock_signature")
    assert hasattr(agent_shield, "mock_only")
    assert hasattr(agent_shield, "timeout")
    assert hasattr(agent_shield, "TimeoutViolationError")
    assert hasattr(agent_shield, "limit_memory")
    assert hasattr(agent_shield, "MemoryViolationError")
    assert hasattr(agent_shield, "restrict_network")
    assert hasattr(agent_shield, "NetworkViolationError")
    assert hasattr(agent_shield, "prompt_assert")
    assert hasattr(agent_shield, "PromptAssertionError")
    assert hasattr(agent_shield, "init_config")
    assert hasattr(agent_shield, "restrict_fs")
    assert hasattr(agent_shield, "FilesystemViolationError")
    assert hasattr(agent_shield, "no_side_effects")
    assert hasattr(agent_shield, "SideEffectViolationError")
    assert hasattr(agent_shield, "ComplexityViolationError")
    
    assert agent_shield.shield is not None
    assert agent_shield.ShieldViolationError is not None
    assert agent_shield.freeze is not None
    assert agent_shield.prompt_inject is not None
    assert agent_shield.lock_signature is not None
    assert agent_shield.mock_only is not None
    assert agent_shield.timeout is not None
    assert agent_shield.TimeoutViolationError is not None
    assert agent_shield.limit_memory is not None
    assert agent_shield.MemoryViolationError is not None
    assert agent_shield.restrict_network is not None
    assert agent_shield.NetworkViolationError is not None
    assert agent_shield.prompt_assert is not None
    assert agent_shield.PromptAssertionError is not None
    assert agent_shield.init_config is not None
    assert agent_shield.restrict_fs is not None
    assert agent_shield.FilesystemViolationError is not None
    assert agent_shield.no_side_effects is not None
    assert agent_shield.SideEffectViolationError is not None
    assert agent_shield.ComplexityViolationError is not None


def test_prompt_inject_modifies_docstring():
    """Verifies that @prompt_inject correctly injects AI architect constraints into docstrings."""
    from agent_shield.injector import prompt_inject

    @prompt_inject("Test instruction")
    def my_db_function():
        """This function connects to the db."""
        return "connected"

    expected_block = (
        "=== AI ASSISTANT ARCHITECTURAL CONSTRAINT ===\n"
        "Test instruction\n"
        "============================================="
    )
    
    assert my_db_function.__doc__ is not None
    assert expected_block in my_db_function.__doc__
    assert "This function connects to the db." in my_db_function.__doc__
    assert my_db_function() == "connected"
    assert my_db_function.__name__ == "my_db_function"

    # Test function without initial docstring
    @prompt_inject("Another instruction")
    def empty_doc_function():
        pass

    assert empty_doc_function.__doc__ is not None
    assert "Another instruction" in empty_doc_function.__doc__


def test_lock_signature_tamper_detection():
    """Verifies that @lock_signature registers a signature and blocks modifications with ShieldViolationError."""
    from agent_shield.signature_lock import lock_signature

    # 1. Clean the key from registry if it exists
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lockfile_path = os.path.join(project_root, "shield_reports", "locked_signatures.json")
    
    if os.path.exists(lockfile_path):
        try:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                data = json.loads(content) if content else {}
        except Exception:
            data = {}
        data.pop("my_locked_function", None)
        with open(lockfile_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
    # 2. Define a function and lock its signature
    @lock_signature
    def my_locked_function(x: int, y: str = "default") -> bool:
        return True
        
    # Check that it is registered
    assert os.path.exists(lockfile_path)
    with open(lockfile_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "my_locked_function" in data
    
    # 3. Modify the signature in the registry to simulate an unauthorized change
    data["my_locked_function"] = "(x: float) -> bool"  # different signature
    with open(lockfile_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    # 4. Try defining the function again and verify it raises ShieldViolationError
    with pytest.raises(ShieldViolationError) as exc_info:
        @lock_signature
        def my_locked_function(x: int, y: str = "default") -> bool:
            return True
            
    assert "Function signature of 'my_locked_function' is locked by the architect and cannot be modified" in str(exc_info.value)
    
    # Cleanup
    with open(lockfile_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.pop("my_locked_function", None)
    with open(lockfile_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def test_mock_only_raises_error_in_test_env():
    """Verifies that @mock_only raises ShieldViolationError when run directly in a test environment."""
    from agent_shield.sandbox import mock_only

    @mock_only
    def send_production_email():
        return "sent"

    with pytest.raises(ShieldViolationError) as exc_info:
        send_production_email()
        
    assert "is marked @mock_only but was executed directly in a test environment without a mock" in str(exc_info.value)


def test_mock_only_runs_outside_test_env():
    """Verifies that @mock_only executes successfully when not running in a test environment."""
    import sys
    from agent_shield.sandbox import mock_only

    @mock_only
    def send_production_email():
        return "sent"

    # Backup modules
    pytest_ref = sys.modules.pop("pytest", None)
    unittest_ref = sys.modules.pop("unittest", None)

    try:
        assert send_production_email() == "sent"
    finally:
        # Restore modules
        if pytest_ref is not None:
            sys.modules["pytest"] = pytest_ref
        if unittest_ref is not None:
            sys.modules["unittest"] = unittest_ref


def test_lock_signature_violates_on_parameter_change():
    """Verify that if a function's parameters are modified after being locked in the JSON registry, it raises ShieldViolationError."""
    from agent_shield.signature_lock import lock_signature

    # 1. Clean the registry key if it exists
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lockfile_path = os.path.join(project_root, "shield_reports", "locked_signatures.json")
    
    if os.path.exists(lockfile_path):
        try:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                data = json.loads(content) if content else {}
        except Exception:
            data = {}
        data.pop("tampered_signature_func", None)
        with open(lockfile_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
    # 2. Define function initially and lock it
    @lock_signature
    def tampered_signature_func(a: int, b: str) -> None:
        pass
        
    # 3. Tamper the signature in the JSON registry
    with open(lockfile_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["tampered_signature_func"] = "(a: float, b: str) -> None"  # Changed a: int to a: float
    with open(lockfile_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    # 4. Redefining it with the original signature should now fail because it doesn't match the tampered registry
    with pytest.raises(ShieldViolationError) as exc_info:
        @lock_signature
        def tampered_signature_func(a: int, b: str) -> None:
            pass
            
    assert "Function signature of 'tampered_signature_func' is locked by the architect" in str(exc_info.value)
    
    # Cleanup
    with open(lockfile_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.pop("tampered_signature_func", None)
    with open(lockfile_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def test_mock_only_passes_if_properly_mocked():
    """Verify that when properly mocked using patch, the @mock_only function bypasses the wrapper."""
    from unittest.mock import patch
    
    # Patch the function to return a mock value and verify it bypasses the wrapper
    with patch(f"{__name__}.module_level_mock_only_func", return_value="mocked-value"):
        assert module_level_mock_only_func() == "mocked-value"


def test_shield_allowed_imports_whitelist():
    """Verifies that only modules in allowed_imports whitelist can be imported."""
    # Importing math which is whitelisted should pass
    @shield(allowed_imports=["math"])
    def import_allowed():
        import math
        return math.sqrt(4)
        
    assert import_allowed() == 2.0
    
    # Importing os which is NOT whitelisted should fail
    with pytest.raises(ShieldViolationError) as exc_info:
        @shield(allowed_imports=["math"])
        def import_disallowed():
            import os
            return os.name
            
    assert "contains disallowed imports: os" in str(exc_info.value)
    
    # Verify the JSON report was generated
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "disallowed_import"
    assert report["function_name"] == "import_disallowed"
    assert "os" in report["details"]["disallowed_imports"]


def test_timeout_raises_error():
    """Verifies that @timeout raises TimeoutViolationError when function execution takes too long."""
    import time
    from agent_shield import timeout, TimeoutViolationError

    @timeout(0.1)
    def slow_function():
        time.sleep(0.5)
        return "done"

    with pytest.raises(TimeoutViolationError) as exc_info:
        slow_function()

    assert "execution timed out after 0.1 seconds" in str(exc_info.value)


def test_timeout_passes_within_limit():
    """Verifies that functions executing within the limit pass successfully."""
    from agent_shield import timeout
    import time

    @timeout(0.5)
    def fast_function():
        time.sleep(0.05)
        return "success"

    assert fast_function() == "success"


def test_limit_memory_raises_error():
    """Verifies that @limit_memory raises MemoryViolationError when function allocates too much memory."""
    from agent_shield import limit_memory, MemoryViolationError
    import time

    # Let's set a low limit of 30 MB
    @limit_memory(max_mb=30.0)
    def memory_heavy_function():
        # Allocate 50 MB
        data = b"x" * (50 * 1024 * 1024)
        # Add a tiny sleep to allow the background monitor thread to catch it
        time.sleep(0.1)
        return len(data)

    with pytest.raises(MemoryViolationError) as exc_info:
        memory_heavy_function()

    assert "exceeded memory limit of 30.0 MB" in str(exc_info.value)

    # Verify JSON report was created
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "memory_limit_exceeded"
    assert report["function_name"] == "memory_heavy_function"
    assert report["details"]["limit_kb"] == 30 * 1024


def test_limit_memory_passes_within_limit():
    """Verifies that @limit_memory allows functions executing within the memory limit to complete."""
    from agent_shield import limit_memory
    import time

    # Set a high limit of 100 MB
    @limit_memory(max_mb=100.0)
    def normal_function():
        # Allocate 5 MB
        data = b"x" * (5 * 1024 * 1024)
        time.sleep(0.1)
        return len(data)

    assert normal_function() == 5 * 1024 * 1024


def test_restrict_network_blocks_unauthorized():
    """Verifies that attempting to connect to a host not inallowed_hosts raises NetworkViolationError."""
    import socket
    from agent_shield import restrict_network, NetworkViolationError

    @restrict_network(allowed_hosts=["localhost", "127.0.0.1"])
    def unauthorized_call():
        s = socket.socket()
        # Trying to connect to a non-whitelisted host (google.com)
        s.connect(("google.com", 80))

    with pytest.raises(NetworkViolationError) as exc_info:
        unauthorized_call()

    assert "attempted unauthorized connection to host 'google.com'" in str(exc_info.value)

    # Verify JSON report was created
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "network_violation"
    assert report["function_name"] == "unauthorized_call"
    assert report["details"]["attempted_host"] == "google.com"


def test_restrict_network_permits_authorized():
    """Verifies that connecting to a whitelisted host bypasses the decorator check and reaches socket layers."""
    import socket
    from agent_shield import restrict_network, NetworkViolationError

    # Connect to localhost on a random port (which will raise ConnectionRefusedError,
    # proving it bypassed the decorator and reached the socket level).
    @restrict_network(allowed_hosts=["localhost"])
    def authorized_call():
        s = socket.socket()
        s.connect(("localhost", 54321))

    # Expect ConnectionRefusedError (or OSError) indicating it passed decorator whitelisting
    with pytest.raises(OSError) as exc_info:
        authorized_call()

    # It must NOT be a NetworkViolationError
    assert not issubclass(exc_info.type, NetworkViolationError)


def test_prompt_assert_mocked_success():
    """Verifies that @prompt_assert allows execution when the mock registry returns success."""
    from agent_shield.semantic import register_prompt_assert_mock, clear_prompt_assert_mocks, prompt_assert
    
    register_prompt_assert_mock("successful_semantic_function", satisfied=True)
    
    try:
        @prompt_assert("This function must compute the square of x")
        def successful_semantic_function(x):
            return x * x
            
        assert successful_semantic_function(5) == 25
    finally:
        clear_prompt_assert_mocks()


def test_prompt_assert_mocked_failure():
    """Verifies that @prompt_assert raises PromptAssertionError when semantic validation fails."""
    from agent_shield.semantic import register_prompt_assert_mock, clear_prompt_assert_mocks, prompt_assert
    from agent_shield import PromptAssertionError
    
    register_prompt_assert_mock("failed_semantic_function", satisfied=False, reason="Function contains print statements which is forbidden.")
    
    try:
        with pytest.raises(PromptAssertionError) as exc_info:
            @prompt_assert("This function must be completely pure.")
            def failed_semantic_function():
                print("impure side effect")
                return 42
                
        assert "violated semantic constraint" in str(exc_info.value)
        assert "Function contains print statements" in str(exc_info.value)
        
        # Verify JSON report was created
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
        assert os.path.exists(report_path)
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        assert report["violation_type"] == "prompt_assertion_violation"
        assert report["function_name"] == "failed_semantic_function"
        assert report["details"]["reason"] == "Function contains print statements which is forbidden."
    finally:
        clear_prompt_assert_mocks()


def test_config_auto_decoration(tmp_path):
    """Verifies that creating a shield.yaml auto-decorates modules at import time."""
    import sys
    from agent_shield.config import init_config
    from agent_shield import TimeoutViolationError
    
    # 1. Create a dummy test file
    dummy_code = """
import time

def my_slow_config_func():
    time.sleep(0.5)
    return "done"
"""
    dummy_file = tmp_path / "config_dummy.py"
    dummy_file.write_text(dummy_code)
    
    # Add tmp_path to Python path so we can import it
    sys.path.insert(0, str(tmp_path))
    
    # 2. Create shield.yaml config in tmp_path
    config_yaml = """
rules:
  - pattern: "config_dummy"
    timeout: 0.05
"""
    yaml_file = tmp_path / "shield.yaml"
    yaml_file.write_text(config_yaml)
    
    try:
        # Clear module status and hook up the custom config path
        sys.modules.pop("config_dummy", None)
        init_config(config_path=str(yaml_file))
        
        # 3. Import and run function
        import config_dummy
        
        with pytest.raises(TimeoutViolationError) as exc_info:
            config_dummy.my_slow_config_func()
            
        assert "execution timed out after 0.05 seconds" in str(exc_info.value)
    finally:
        # Cleanup
        sys.path.remove(str(tmp_path))
        sys.modules.pop("config_dummy", None)
        # Restore default import hook
        import builtins
        from agent_shield.config import _original_import
        builtins.__import__ = _original_import
        from agent_shield.config import _hook_applied
        import agent_shield.config
        agent_shield.config._hook_applied = False
        agent_shield.config._decorated_modules.clear()


def test_restrict_fs_blocks_unauthorized_write(tmp_path):
    """Verifies that writing to a non-whitelisted path raises FilesystemViolationError."""
    from agent_shield import restrict_fs, FilesystemViolationError
    
    allowed_dir = str(tmp_path / "allowed")
    os.makedirs(allowed_dir, exist_ok=True)
    
    unauthorized_file = str(tmp_path / "secret.txt")
    
    @restrict_fs(allow_write=[allowed_dir])
    def do_file_write():
        with open(unauthorized_file, "w") as f:
            f.write("confidential")
            
    with pytest.raises(FilesystemViolationError) as exc_info:
        do_file_write()
        
    assert "attempted unauthorized 'write' to path" in str(exc_info.value)
    assert "secret.txt" in str(exc_info.value)
    
    # Verify report was generated
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["violation_type"] == "filesystem_violation"
    assert report["function_name"] == "do_file_write"


def test_restrict_fs_allows_authorized_write(tmp_path):
    """Verifies that writing to an allowed path succeeds."""
    from agent_shield import restrict_fs
    
    allowed_dir = str(tmp_path / "allowed")
    os.makedirs(allowed_dir, exist_ok=True)
    
    allowed_file = str(tmp_path / "allowed" / "test.txt")
    
    @restrict_fs(allow_write=[allowed_dir])
    def do_file_write():
        with open(allowed_file, "w") as f:
            f.write("permitted content")
        return "written"
        
    assert do_file_write() == "written"
    with open(allowed_file, "r") as f:
        assert f.read() == "permitted content"


def test_passive_shield_mode_logs_without_exception():
    """Verifies that when AGENT_SHIELD_PASSIVE is active, violations do not raise exceptions."""
    from agent_shield.contracts import shield, ShieldViolationError
    
    # Enable passive mode
    os.environ["AGENT_SHIELD_PASSIVE"] = "true"
    try:
        # Define a function containing a forbidden import
        # It should execute without raising an error
        @shield(forbidden_imports=["sys"])
        def func_with_sys_import():
            import sys
            return "system-ok"
            
        # The function runs fine even though sys is forbidden
        assert func_with_sys_import() == "system-ok"
        
        # Verify JSON report was still generated
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        report_path = os.path.join(project_root, "shield_reports", "violation_report.json")
        assert os.path.exists(report_path)
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        assert report["violation_type"] == "forbidden_import"
    finally:
        # Disable passive mode
        os.environ.pop("AGENT_SHIELD_PASSIVE", None)


def test_shield_max_complexity_violates():
    """Verifies that a function exceeding max_complexity triggers ComplexityViolationError at definition time."""
    from agent_shield import shield, ComplexityViolationError
    
    with pytest.raises(ComplexityViolationError) as exc_info:
        @shield(max_complexity=2)
        def overly_complex_function(x):
            # Base complexity = 1
            # 3 decision points = complexity of 4
            if x > 10:
                if x < 20:
                    return 1
                else:
                    return 2
            elif x < 5:
                return 3
            return 4
            
    assert "has a cyclomatic complexity of 4, exceeding the limit of 2" in str(exc_info.value)


def test_no_side_effects_mutates_arguments():
    """Verifies that @no_side_effects prevents modifying mutable arguments."""
    from agent_shield import no_side_effects, SideEffectViolationError
    
    @no_side_effects
    def mutate_arg(my_list):
        my_list.append("mutated")
        return my_list
        
    with pytest.raises(SideEffectViolationError) as exc_info:
        mutate_arg([])
        
    assert "mutated its input arguments" in str(exc_info.value)


def test_no_side_effects_mutates_globals():
    """Verifies that @no_side_effects prevents mutating module-level globals."""
    from agent_shield import no_side_effects, SideEffectViolationError
    
    global test_global_state
    test_global_state = "original"
    
    @no_side_effects
    def mutate_global():
        global test_global_state
        test_global_state = "mutated"
        
    with pytest.raises(SideEffectViolationError) as exc_info:
        mutate_global()
        
    assert "mutated module-level globals: test_global_state" in str(exc_info.value)


def test_no_side_effects_writes_stdout():
    """Verifies that @no_side_effects prevents printing output to console."""
    from agent_shield import no_side_effects, SideEffectViolationError
    
    @no_side_effects
    def print_to_console():
        print("side effect output")
        
    with pytest.raises(SideEffectViolationError) as exc_info:
        print_to_console()
        
    assert "printed output to console: 'side effect output'" in str(exc_info.value)


def test_no_side_effects_passes_pure():
    """Verifies that @no_side_effects allows pure functions to execute successfully."""
    from agent_shield import no_side_effects
    
    @no_side_effects
    def pure_function(x, y):
        return x + y
        
    assert pure_function(2, 3) == 5


def test_cli_status_no_report(capsys, monkeypatch, tmp_path):
    """Verifies CLI status command outputs correct message when no report exists."""
    import agent_shield.cli
    monkeypatch.setattr(agent_shield.cli, "find_project_root", lambda: str(tmp_path))
    
    code = agent_shield.cli.main(["status"])
    assert code == 0
    captured = capsys.readouterr()
    assert "No active violation reports found." in captured.out


def test_cli_status_shows_report(capsys, monkeypatch, tmp_path):
    """Verifies CLI status command displays report details and suggested command."""
    import agent_shield.cli
    monkeypatch.setattr(agent_shield.cli, "find_project_root", lambda: str(tmp_path))
    
    reports_dir = tmp_path / "shield_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "violation_report.json"
    
    report_data = {
        "violation_type": "filesystem_violation",
        "function_name": "unsafe_write",
        "file_path": "/workspace/main.py",
        "details": {
            "requested_path": "/etc/passwd",
            "operation": "write"
        },
        "instruction": "Do not modify critical files"
    }
    
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f)
        
    code = agent_shield.cli.main(["status"])
    assert code == 0
    captured = capsys.readouterr()
    
    assert "filesystem_violation" in captured.out
    assert "unsafe_write" in captured.out
    assert "Do not modify critical files" in captured.out
    assert "python -m agent_shield whitelist --path \"/etc/passwd\" --write" in captured.out


def test_cli_whitelist_creates_yaml(monkeypatch, tmp_path):
    """Verifies that running whitelist command creates shield.yaml with rules."""
    import agent_shield.cli
    monkeypatch.setattr(agent_shield.cli, "find_project_root", lambda: str(tmp_path))
    
    yaml_path = tmp_path / "shield.yaml"
    assert not yaml_path.exists()
    
    code = agent_shield.cli.main(["whitelist", "--import", "os", "--pattern", "tests.*"])
    assert code == 0
    assert yaml_path.exists()
    
    with open(yaml_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert 'pattern: "tests.*"' in content
    assert 'allowed_imports: ["os"]' in content


def test_cli_whitelist_updates_existing_yaml(monkeypatch, tmp_path):
    """Verifies that running whitelist command updates an existing shield.yaml and removes violation report."""
    import agent_shield.cli
    monkeypatch.setattr(agent_shield.cli, "find_project_root", lambda: str(tmp_path))
    
    yaml_path = tmp_path / "shield.yaml"
    initial_content = """rules:
  - pattern: "*"
    allowed_imports: ["math"]
"""
    with open(yaml_path, "w", encoding="utf-8") as f:
        f.write(initial_content)
        
    reports_dir = tmp_path / "shield_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "violation_report.json"
    report_file.write_text("{}", encoding="utf-8")
    
    # 1. Whitelist another import
    code = agent_shield.cli.main(["whitelist", "--import", "json"])
    assert code == 0
    
    # 2. Whitelist a path
    code = agent_shield.cli.main(["whitelist", "--path", "/tmp", "--read"])
    assert code == 0
    
    # 3. Whitelist a host
    code = agent_shield.cli.main(["whitelist", "--host", "api.github.com"])
    assert code == 0
    
    with open(yaml_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert 'allowed_imports: ["math", "json"]' in content
    assert 'allow_read: ["/tmp"]' in content
    assert 'restrict_network: ["api.github.com"]' in content
    
    # Check that the violation report was deleted
    assert not report_file.exists()




