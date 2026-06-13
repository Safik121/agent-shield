import functools
import threading
import os
import sys
import inspect
import json
import builtins
from agent_shield.contracts import FilesystemViolationError

# Store original filesystem functions
_orig_open = builtins.open
_orig_remove = os.remove
_orig_unlink = getattr(os, "unlink", None)
_orig_rename = os.rename
_orig_replace = os.replace
_orig_mkdir = os.mkdir
_orig_makedirs = os.makedirs
_orig_rmdir = os.rmdir

# Active thread restriction registry: thread_id -> (allow_read, allow_write, func, project_root)
_fs_restricted_threads = {}
_lock = threading.Lock()
_local_state = threading.local()

def _is_python_system_path(path: str) -> bool:
    """Checks if a path belongs to standard Python runtime, site-packages, or interpreter libraries."""
    path = os.path.abspath(path)
    
    # Allow imports of python source/bytecode files
    if path.endswith((".py", ".pyc")):
        return True
        
    for sys_path in (sys.prefix, sys.base_prefix):
        sys_path = os.path.abspath(sys_path)
        if path.startswith(sys_path + os.sep):
            return True
            
    # Also check typical sys.path entries
    for p in sys.path:
        if p:
            abs_p = os.path.abspath(p)
            if "site-packages" in abs_p or "dist-packages" in abs_p:
                if path.startswith(abs_p + os.sep):
                    return True
                    
    return False

def _is_path_allowed(path: str, allowed_list: list[str]) -> bool:
    """Verifies if path resides inside any of the directories/files in allowed_list."""
    path = os.path.abspath(path)
    
    # Bypass for Python runtime/imports
    if _is_python_system_path(path):
        return True
        
    for allowed in allowed_list:
        allowed = os.path.abspath(os.path.expanduser(allowed))
        if path == allowed or path.startswith(allowed + os.sep):
            return True
    return False

def _handle_fs_violation(path: str, operation: str, allowed_list: list[str], func, project_root: str):
    reports_dir = os.path.join(project_root, "shield_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    try:
        func_file = inspect.getfile(func)
        func_abs_file = os.path.abspath(func_file)
    except Exception:
        func_abs_file = "unknown"
        
    report = {
        "violation_type": "filesystem_violation",
        "function_name": func.__name__,
        "file_path": func_abs_file,
        "details": {
            "attempted_path": path,
            "operation": operation,
            "allowed_paths": allowed_list
        },
        "instruction": (
            f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
            f"attempted an unauthorized '{operation}' operation on '{path}'.\n"
            f"Allowed paths: {', '.join(allowed_list)}.\n"
            f"Please remove this file operation or write to an allowed path."
        )
    }
    report_path = os.path.join(reports_dir, "violation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    error_msg = f"Function '{func.__name__}' attempted unauthorized '{operation}' to path '{path}'."
    
    is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
    if is_passive:
        print(f"Warning: agent-shield passive mode violation detected: {error_msg}")
    else:
        raise FilesystemViolationError(error_msg)

def _check_fs_access(path: str, operation_type: str):
    thread_id = threading.get_ident()
    with _lock:
        restricted = _fs_restricted_threads.get(thread_id)
        
    if restricted:
        if getattr(_local_state, "in_check", False):
            return
            
        _local_state.in_check = True
        try:
            allow_read, allow_write, func, project_root = restricted
            abs_path = os.path.abspath(os.path.expanduser(str(path)))
            if operation_type == "write":
                if allow_write is not None and not _is_path_allowed(abs_path, allow_write):
                    _handle_fs_violation(abs_path, "write", allow_write, func, project_root)
            else:
                if allow_read is not None and not _is_path_allowed(abs_path, allow_read):
                    _handle_fs_violation(abs_path, "read", allow_read, func, project_root)
        finally:
            _local_state.in_check = False

# Custom wrappers
def _custom_open(file, mode='r', *args, **kwargs):
    # If the file argument is a path (str, bytes or Path object)
    if isinstance(file, (str, bytes, os.PathLike)):
        # Determine operation type
        mode_str = str(mode)
        is_writing = any(char in mode_str for char in ('w', 'a', '+', 'x'))
        _check_fs_access(file, "write" if is_writing else "read")
    return _orig_open(file, mode, *args, **kwargs)

def _custom_remove(path, *args, **kwargs):
    _check_fs_access(path, "write")
    return _orig_remove(path, *args, **kwargs)

def _custom_unlink(path, *args, **kwargs):
    _check_fs_access(path, "write")
    if _orig_unlink:
        return _orig_unlink(path, *args, **kwargs)

def _custom_rename(src, dst, *args, **kwargs):
    _check_fs_access(src, "write")
    _check_fs_access(dst, "write")
    return _orig_rename(src, dst, *args, **kwargs)

def _custom_replace(src, dst, *args, **kwargs):
    _check_fs_access(src, "write")
    _check_fs_access(dst, "write")
    return _orig_replace(src, dst, *args, **kwargs)

def _custom_mkdir(path, *args, **kwargs):
    _check_fs_access(path, "write")
    return _orig_mkdir(path, *args, **kwargs)

def _custom_makedirs(name, *args, **kwargs):
    _check_fs_access(name, "write")
    return _orig_makedirs(name, *args, **kwargs)

def _custom_rmdir(path, *args, **kwargs):
    _check_fs_access(path, "write")
    return _orig_rmdir(path, *args, **kwargs)

# Apply global monkeypatches
builtins.open = _custom_open
os.remove = _custom_remove
if _orig_unlink:
    os.unlink = _custom_unlink
os.rename = _custom_rename
os.replace = _custom_replace
os.mkdir = _custom_mkdir
os.makedirs = _custom_makedirs
os.rmdir = _custom_rmdir

def restrict_fs(allow_read: list[str] = None, allow_write: list[str] = None):
    """Decorator to restrict filesystem access of a function.
    
    If the function attempts filesystem operations outside allowed directories,
    it raises a FilesystemViolationError.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            thread_id = threading.get_ident()
            
            with _lock:
                _fs_restricted_threads[thread_id] = (allow_read, allow_write, func, project_root)
                
            try:
                return func(*args, **kwargs)
            finally:
                with _lock:
                    _fs_restricted_threads.pop(thread_id, None)
        return wrapper
    return decorator
