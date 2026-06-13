import os
import json
import hashlib
import inspect
import typing
from agent_shield.contracts import ShieldViolationError

def freeze(func: typing.Callable) -> typing.Callable:
    """Decorator to freeze a function's code at definition time.
    
    Verifies that the function's source code has not changed since the first
    time it was registered in `shield_reports/frozen_functions.json`. If it has,
    raises ShieldViolationError.
    """
    try:
        source = inspect.getsource(func)
        func_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    except Exception:
        # Gracefully proceed if the source cannot be retrieved (e.g. dynamic functions)
        return func

    # Determine path to the frozen functions lockfile
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    reports_dir = os.path.join(project_root, "shield_reports")
    lockfile_path = os.path.join(reports_dir, "frozen_functions.json")

    # Ensure reports directory exists
    os.makedirs(reports_dir, exist_ok=True)

    # Load existing frozen functions configuration
    frozen_data: dict[str, str] = {}
    if os.path.exists(lockfile_path):
        try:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    frozen_data = json.loads(content)
        except Exception:
            # Fallback to an empty configuration if reading fails
            frozen_data = {}

    func_name = func.__name__

    if func_name not in frozen_data:
        # Register the function's initial state
        frozen_data[func_name] = func_hash
        try:
            with open(lockfile_path, "w", encoding="utf-8") as f:
                json.dump(frozen_data, f, indent=2, ensure_ascii=False)
        except Exception:
            # Ignore write issues (e.g. read-only environments)
            pass
    else:
        # Verify that the function's current hash matches the registered hash
        if frozen_data[func_name] != func_hash:
            raise ShieldViolationError(
                f"Function '{func_name}' is frozen by the architect and cannot be modified."
            )

    return func
