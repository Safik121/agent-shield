import os
import json
import inspect
import typing
from agent_shield.contracts import ShieldViolationError

def lock_signature(func: typing.Callable) -> typing.Callable:
    """Decorator to lock a function's signature at definition time.
    
    Verifies that the function's parameter names, types, order, defaults,
    and return type annotations have not changed since the first time
    it was registered in `shield_reports/locked_signatures.json`.
    If they have, raises ShieldViolationError.
    """
    try:
        sig = inspect.signature(func)
        sig_str = str(sig)
    except Exception:
        # Gracefully proceed if the signature cannot be extracted
        return func

    # Determine path to locked signatures registry
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    reports_dir = os.path.join(project_root, "shield_reports")
    lockfile_path = os.path.join(reports_dir, "locked_signatures.json")

    # Ensure reports directory exists
    os.makedirs(reports_dir, exist_ok=True)

    # Load existing locked signatures config
    locked_data: dict[str, str] = {}
    if os.path.exists(lockfile_path):
        try:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    locked_data = json.loads(content)
        except Exception:
            # Fallback to an empty configuration if reading fails
            locked_data = {}

    func_name = func.__name__

    if func_name not in locked_data:
        # Register the function's initial signature
        locked_data[func_name] = sig_str
        try:
            with open(lockfile_path, "w", encoding="utf-8") as f:
                json.dump(locked_data, f, indent=2, ensure_ascii=False)
        except Exception:
            # Ignore write issues (e.g. read-only environments)
            pass
    else:
        # Verify that the function's current signature matches the locked signature
        if locked_data[func_name] != sig_str:
            raise ShieldViolationError(
                f"Function signature of '{func_name}' is locked by the architect and cannot be modified."
            )

    return func
