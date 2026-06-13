import functools
import copy
import sys
import io
import os
import inspect
import json
import types
from contextlib import redirect_stdout, redirect_stderr
from agent_shield.contracts import SideEffectViolationError

def _is_copyable_global(name, val):
    if isinstance(val, (types.ModuleType, types.FunctionType, types.BuiltinFunctionType, types.MethodType, type)):
        return False
    if name.startswith("__") and name.endswith("__"):
        return False
    return True

def no_side_effects(func=None, *, allow_args_mutation=False, allow_globals=False, allow_stdout=False):
    """Decorator to enforce that a function has no side effects.
    
    Checks for:
    - Mutating input arguments (args/kwargs)
    - Modifying module-level global state
    - Writing to stdout/stderr (e.g. print statements)
    """
    if func is None:
        return lambda f: no_side_effects(
            f,
            allow_args_mutation=allow_args_mutation,
            allow_globals=allow_globals,
            allow_stdout=allow_stdout
        )

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        reports_dir = os.path.join(project_root, "shield_reports")

        # 1. Capture snapshot of arguments
        args_copy = None
        kwargs_copy = None
        if not allow_args_mutation:
            try:
                args_copy = copy.deepcopy(args)
                kwargs_copy = copy.deepcopy(kwargs)
            except Exception:
                pass

        # 2. Capture snapshot of module globals
        globals_snapshot = {}
        func_globals = func.__globals__
        if not allow_globals:
            for k, v in func_globals.items():
                if _is_copyable_global(k, v):
                    try:
                        globals_snapshot[k] = copy.deepcopy(v)
                    except Exception:
                        pass

        def report_and_raise(violation_details: dict, error_msg: str):
            os.makedirs(reports_dir, exist_ok=True)
            
            try:
                func_file = inspect.getfile(func)
                func_abs_file = os.path.abspath(func_file)
            except Exception:
                func_abs_file = "unknown"
                
            report = {
                "violation_type": "side_effect_violation",
                "function_name": func.__name__,
                "file_path": func_abs_file,
                "details": violation_details,
                "instruction": (
                    f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                    f"caused an unauthorized side-effect: {error_msg}\n"
                    f"Please refactor the code to eliminate this side-effect (make the function pure)."
                )
            }
            report_path = os.path.join(reports_dir, "violation_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
            if is_passive:
                print(f"Warning: agent-shield passive mode violation detected: {error_msg}")
            else:
                raise SideEffectViolationError(error_msg)

        # 3. Capture stdout/stderr redirection if not allowed
        if not allow_stdout:
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                result = func(*args, **kwargs)
            captured_stdout = stdout_buf.getvalue()
            captured_stderr = stderr_buf.getvalue()
        else:
            result = func(*args, **kwargs)
            captured_stdout = ""
            captured_stderr = ""

        # 4. Check for Side-Effects
        if not allow_stdout and (captured_stdout or captured_stderr):
            output = (captured_stdout + captured_stderr).strip()
            report_and_raise(
                violation_details={"stdout_captured": output},
                error_msg=f"Function '{func.__name__}' printed output to console: '{output}'"
            )

        if not allow_args_mutation and args_copy is not None:
            if args != args_copy or kwargs != kwargs_copy:
                report_and_raise(
                    violation_details={"args_mutated": True},
                    error_msg=f"Function '{func.__name__}' mutated its input arguments."
                )

        if not allow_globals:
            mutated_globals = []
            for k, snap_v in globals_snapshot.items():
                current_v = func_globals.get(k)
                try:
                    if current_v != snap_v:
                        mutated_globals.append(k)
                except Exception:
                    pass
            if mutated_globals:
                report_and_raise(
                    violation_details={"mutated_globals": mutated_globals},
                    error_msg=f"Function '{func.__name__}' mutated module-level globals: {', '.join(mutated_globals)}"
                )

        return result
    return wrapper
