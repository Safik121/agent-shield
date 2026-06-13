import os
import json
import inspect
import functools
import typing

class ShieldViolationError(Exception):
    """Exception raised when an architectural contract or boundary is violated."""
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


def shield(func):
    """Decorator to enforce function contract boundaries at runtime.
    
    Currently monitors:
    - Return type annotation vs. actual return type.
    """
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
            
            # Locate project root directory (parent of 'agent_shield' package)
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            reports_dir = os.path.join(project_root, "shield_reports")
            
            # Ensure report directory exists
            os.makedirs(reports_dir, exist_ok=True)
            
            # Find the file path of the decorated function
            try:
                func_file = inspect.getfile(func)
                func_abs_file = os.path.abspath(func_file)
            except Exception:
                func_abs_file = "unknown"
                
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
                
            raise ShieldViolationError(
                f"Function '{func.__name__}' returned type '{actual_name}' "
                f"instead of expected '{expected_name}'."
            )
            
        return result
    return wrapper
