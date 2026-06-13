import os
import json
import inspect
import functools
import typing
import contextvars

class ShieldViolationError(Exception):
    """Exception raised when an architectural contract or boundary is violated."""
    pass


class TimeoutViolationError(ShieldViolationError):
    """Exception raised when function execution exceeds the allocated time limit."""
    pass


class MemoryViolationError(ShieldViolationError):
    """Exception raised when function execution memory allocation exceeds the limit."""
    pass


class NetworkViolationError(ShieldViolationError):
    """Exception raised when function attempts an unauthorized network connection."""
    pass


class PromptAssertionError(ShieldViolationError):
    """Exception raised when function fails to satisfy a semantic prompt assertion."""
    pass


class FilesystemViolationError(ShieldViolationError):
    """Exception raised when function attempts an unauthorized filesystem operation."""
    pass


class SideEffectViolationError(ShieldViolationError):
    """Exception raised when function causes an unauthorized side-effect."""
    pass


class ComplexityViolationError(ShieldViolationError):
    """Exception raised when function exceeds maximum allowed complexity."""
    pass


class SubprocessViolationError(ShieldViolationError):
    """Exception raised when function attempts an unauthorized subprocess execution."""
    pass


class SecretsLeakViolationError(ShieldViolationError):
    """Exception raised when function attempts to leak secrets or PII."""
    pass


class CallLimitViolationError(ShieldViolationError):
    """Exception raised when function exceeds allowed number of network calls."""
    pass


class EnvironmentViolationError(ShieldViolationError):
    """Exception raised when function attempts to mutate system environment variables."""
    pass


def _is_matching_type(value: typing.Any, expected_type: typing.Any) -> bool:
    """Helper to check if a value matches the expected type annotation."""
    if expected_type is inspect.Signature.empty:
        return True
    if expected_type is None or expected_type is type(None):
        return value is None

    # Resolve typing generics (e.g., dict[str, int], typing.List[int])
    origin = typing.get_origin(expected_type)
    if origin is not None:
        # Handle Union types (including modern X | Y syntax via UnionType)
        if origin is typing.Union or (hasattr(typing, "UnionType") and origin is typing.UnionType):
            args = typing.get_args(expected_type)
            return any(_is_matching_type(value, arg) for arg in args)
        expected_type = origin

    # Verify against standard class types
    if isinstance(expected_type, type):
        return isinstance(value, expected_type)
        
    return True


def _get_type_name(t: typing.Any) -> str:
    """Helper to get a user-friendly string representation of a type annotation."""
    if isinstance(t, type):
        return t.__name__
    return str(t)


def shield(
    forbidden_imports: list[str] = None,
    allow_unsafe: bool = False,
    allow_globals: bool = False,
    allowed_imports: list[str] = None,
    max_complexity: int = None
):
    """Decorator to enforce function contract boundaries.
    
    Supports:
    - Definition-time: AST analysis for forbidden imports, allowed imports, dangerous functions (eval/exec), global scope usage, and complexity.
    - Runtime: Return type validation against type hints.
    
    Usage:
        @shield(forbidden_imports=["os"], allow_unsafe=False, allow_globals=False)
        def my_func(): ...
    """
    # Handle usage without parentheses: @shield
    if callable(forbidden_imports):
        func = forbidden_imports
        return _decorator(func, None, False, False, None, None)
        
    def decorator(func):
        return _decorator(func, forbidden_imports, allow_unsafe, allow_globals, allowed_imports, max_complexity)
        
    return decorator


def _decorator(func, forbidden_imports, allow_unsafe, allow_globals, allowed_imports, max_complexity):
    # Locate project root and prepare reports directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    reports_dir = os.path.join(project_root, "shield_reports")
    
    try:
        func_file = inspect.getfile(func)
        func_abs_file = os.path.abspath(func_file)
    except Exception:
        func_abs_file = "unknown"

    # Helper to generate violation report and raise error
    def report_and_raise(violation_type: str, details: dict, error_msg: str, instruction: str, exc_class=ShieldViolationError):
        os.makedirs(reports_dir, exist_ok=True)
        report = {
            "violation_type": violation_type,
            "function_name": func.__name__,
            "file_path": func_abs_file,
            "details": details,
            "instruction": instruction
        }
        report_path = os.path.join(reports_dir, "violation_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
        if is_passive:
            print(f"Warning: agent-shield passive mode violation detected: {error_msg}")
        else:
            raise exc_class(error_msg)

    # 1. Forbidden Imports Check
    if forbidden_imports:
        from agent_shield.inspector import find_forbidden_imports
        violations = find_forbidden_imports(func, forbidden_imports)
        if violations:
            report_and_raise(
                violation_type="forbidden_import",
                details={"forbidden_imports": violations},
                error_msg=f"Function '{func.__name__}' contains forbidden imports: {', '.join(violations)}",
                instruction=(
                    f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                    f"contains forbidden imports: {', '.join(violations)}. "
                    f"Please refactor the code to remove these imports or utilize allowed alternatives."
                )
            )

    # 1.5. Allowed Imports Check (Whitelist)
    if allowed_imports is not None:
        from agent_shield.inspector import find_disallowed_imports
        violations = find_disallowed_imports(func, allowed_imports)
        if violations:
            report_and_raise(
                violation_type="disallowed_import",
                details={"disallowed_imports": violations},
                error_msg=f"Function '{func.__name__}' contains disallowed imports: {', '.join(violations)}",
                instruction=(
                    f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                    f"contains disallowed imports: {', '.join(violations)}. "
                    f"Please refactor the code to only use whitelisted imports: {', '.join(allowed_imports)}."
                )
            )

    # 2. Dangerous Functions Check
    if not allow_unsafe:
        from agent_shield.inspector import detect_dangerous_functions
        violations = detect_dangerous_functions(func)
        if violations:
            report_and_raise(
                violation_type="dangerous_execution",
                details={"dangerous_functions": violations},
                error_msg=f"Function '{func.__name__}' contains calls to dangerous functions: {', '.join(violations)}",
                instruction=(
                    f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                    f"contains calls to dangerous execution functions: {', '.join(violations)}. "
                    f"Dynamic execution via eval/exec is forbidden. Please rewrite the logic without using eval or exec."
                )
            )

    # 3. Global Scope Check
    if not allow_globals:
        from agent_shield.inspector import detect_global_keyword
        if detect_global_keyword(func):
            report_and_raise(
                violation_type="global_scope_violation",
                details={"global_keyword_detected": True},
                error_msg=f"Function '{func.__name__}' modifies global state using the 'global' keyword.",
                instruction=(
                    f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                    f"utilizes the 'global' keyword to modify global variables. "
                    f"Modifying global state inside functions is prohibited. "
                    f"Please refactor the function to pass state as parameters or return values instead."
                )
            )

    # 4. Hardcoded Secrets Check
    from agent_shield.inspector import detect_hardcoded_secrets
    secrets = detect_hardcoded_secrets(func)
    if secrets:
        report_and_raise(
            violation_type="hardcoded_secret",
            details={"hardcoded_secrets": secrets},
            error_msg=f"Function '{func.__name__}' contains hardcoded secrets: {', '.join(secrets)}",
            instruction=(
                f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                f"contains hardcoded secret values: {', '.join(secrets)}. "
                f"Storing API keys or credentials directly in source code is a critical security risk. "
                f"Please retrieve these sensitive values from environment variables or a configuration store instead."
            )
        )

    # 5. CPU Lockup Hazard Check
    from agent_shield.inspector import detect_cpu_lockups
    if detect_cpu_lockups(func):
        report_and_raise(
            violation_type="cpu_lockup_hazard",
            details={"cpu_lockup_detected": True},
            error_msg=f"Function '{func.__name__}' contains a potential infinite loop causing a CPU lockup.",
            instruction=(
                f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                f"contains a CPU lockup hazard (an infinite loop with no body statements modifying state or sleeping). "
                f"This can lock up the runtime execution. "
                f"Please ensure the loop contains a proper break condition, sleep interval, or state mutation."
            )
        )

    # 6. Cyclomatic Complexity Check
    if max_complexity is not None:
        from agent_shield.complexity import calculate_cyclomatic_complexity
        comp = calculate_cyclomatic_complexity(func)
        if comp > max_complexity:
            report_and_raise(
                violation_type="complexity_exceeded",
                details={"complexity": comp, "max_complexity": max_complexity},
                error_msg=f"Function '{func.__name__}' has a cyclomatic complexity of {comp}, exceeding the limit of {max_complexity}.",
                instruction=(
                    f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                    f"has a cyclomatic complexity of {comp}, which exceeds the limit of {max_complexity}.\n"
                    f"Please simplify the code by refactoring branching logic (if/for/while/except) or split it into smaller functions."
                ),
                exc_class=ComplexityViolationError
            )

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            
            # Resolve return type hint, falling back if resolve fails (e.g. forward references)
            try:
                hints = typing.get_type_hints(func)
                expected_type = hints.get("return", inspect.Signature.empty)
            except Exception:
                try:
                    sig = inspect.signature(func)
                    expected_type = sig.return_annotation
                except Exception:
                    expected_type = inspect.Signature.empty
                    
            if not _is_matching_type(result, expected_type):
                expected_name = _get_type_name(expected_type)
                actual_name = _get_type_name(type(result))
                
                # Ensure report directory exists
                os.makedirs(reports_dir, exist_ok=True)
                
                report = {
                    "violation_type": "return_type_mismatch",
                    "function_name": func.__name__,
                    "file_path": func_abs_file,
                    "expected_type": expected_name,
                    "actual_type": actual_name,
                    "instruction": (
                        f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                        f"is annotated to return '{expected_name}', but it returned a value of type '{actual_name}'. "
                        f"Please correct the function implementation to return the expected type, or update the "
                        f"return type annotation if the signature needs to be changed."
                    )
                }
                
                report_path = os.path.join(reports_dir, "violation_report.json")
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                    
                error_msg = (
                    f"Function '{func.__name__}' returned type '{actual_name}' "
                    f"instead of expected '{expected_name}'."
                )
                is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
                if is_passive:
                    print(f"Warning: agent-shield passive mode violation detected: {error_msg}")
                else:
                    raise ShieldViolationError(error_msg)
                
            return result
        return wrapper
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Resolve return type hint, falling back if resolve fails (e.g. forward references)
            try:
                hints = typing.get_type_hints(func)
                expected_type = hints.get("return", inspect.Signature.empty)
            except Exception:
                try:
                    sig = inspect.signature(func)
                    expected_type = sig.return_annotation
                except Exception:
                    expected_type = inspect.Signature.empty
                    
            if not _is_matching_type(result, expected_type):
                expected_name = _get_type_name(expected_type)
                actual_name = _get_type_name(type(result))
                
                # Ensure report directory exists
                os.makedirs(reports_dir, exist_ok=True)
                
                report = {
                    "violation_type": "return_type_mismatch",
                    "function_name": func.__name__,
                    "file_path": func_abs_file,
                    "expected_type": expected_name,
                    "actual_type": actual_name,
                    "instruction": (
                        f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                        f"is annotated to return '{expected_name}', but it returned a value of type '{actual_name}'. "
                        f"Please correct the function implementation to return the expected type, or update the "
                        f"return type annotation if the signature needs to be changed."
                    )
                }
                
                report_path = os.path.join(reports_dir, "violation_report.json")
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                    
                error_msg = (
                    f"Function '{func.__name__}' returned type '{actual_name}' "
                    f"instead of expected '{expected_name}'."
                )
                is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
                if is_passive:
                    print(f"Warning: agent-shield passive mode violation detected: {error_msg}")
                else:
                    raise ShieldViolationError(error_msg)
                
            return result
        return wrapper


# Active environment restriction context
_env_restricted_context = contextvars.ContextVar("env_restricted_context", default=None)

# Monkeypatch os._Environ methods
_orig_environ_setitem = os._Environ.__setitem__
_orig_environ_delitem = os._Environ.__delitem__

def _custom_environ_setitem(self, key, value):
    info = _env_restricted_context.get()
    if info:
        func = info["func"]
        project_root = info["project_root"]
        reports_dir = os.path.join(project_root, "shield_reports")
        os.makedirs(reports_dir, exist_ok=True)
        try:
            func_file = inspect.getfile(func)
            func_abs_file = os.path.abspath(func_file)
        except Exception:
            func_abs_file = "unknown"
        
        report = {
            "violation_type": "environment_violation",
            "function_name": func.__name__,
            "file_path": func_abs_file,
            "details": {
                "operation": "setitem",
                "key": str(key)
            },
            "instruction": f"Do not mutate environment variable '{key}' in restricted environment."
        }
        report_path = os.path.join(reports_dir, "violation_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        raise EnvironmentViolationError(f"Environment Sandbox: mutation of environment variable '{key}' is forbidden.")
        
    return _orig_environ_setitem(self, key, value)

def _custom_environ_delitem(self, key):
    info = _env_restricted_context.get()
    if info:
        func = info["func"]
        project_root = info["project_root"]
        reports_dir = os.path.join(project_root, "shield_reports")
        os.makedirs(reports_dir, exist_ok=True)
        try:
            func_file = inspect.getfile(func)
            func_abs_file = os.path.abspath(func_file)
        except Exception:
            func_abs_file = "unknown"
            
        report = {
            "violation_type": "environment_violation",
            "function_name": func.__name__,
            "file_path": func_abs_file,
            "details": {
                "operation": "delitem",
                "key": str(key)
            },
            "instruction": f"Do not delete environment variable '{key}' in restricted environment."
        }
        report_path = os.path.join(reports_dir, "violation_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        raise EnvironmentViolationError(f"Environment Sandbox: deletion of environment variable '{key}' is forbidden.")
        
    return _orig_environ_delitem(self, key)

# Apply global environ monkeypatch
os._Environ.__setitem__ = _custom_environ_setitem
os._Environ.__delitem__ = _custom_environ_delitem

def restrict_env(allow_mutation: bool = False):
    """Decorator to prevent modifications to environment variables (os.environ) during execution."""
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                if not allow_mutation:
                    token = _env_restricted_context.set({
                        "func": func,
                        "project_root": project_root
                    })
                else:
                    token = None
                    
                try:
                    return await func(*args, **kwargs)
                finally:
                    if token is not None:
                        _env_restricted_context.reset(token)
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                if not allow_mutation:
                    token = _env_restricted_context.set({
                        "func": func,
                        "project_root": project_root
                    })
                else:
                    token = None
                    
                try:
                    return func(*args, **kwargs)
                finally:
                    if token is not None:
                        _env_restricted_context.reset(token)
            return wrapper
    return decorator
