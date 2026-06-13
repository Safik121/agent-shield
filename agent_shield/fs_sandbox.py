import functools
import os
import sys
import inspect
import json
import builtins
import contextvars
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

# Active thread/task restriction context: (allow_read, allow_write, func, project_root)
_fs_restricted_context = contextvars.ContextVar("fs_restricted_context", default=None)
_local_state = contextvars.ContextVar("local_state", default=False)

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

def _report_violation_and_raise(violated_path: str, operation: str, allowed_list: list[str], func, project_root: str):
    reports_dir = os.path.join(project_root, "shield_reports")
    
    # Enable re-entrancy tracker to prevent recursion when making directories or writing report
    _local_state.set(True)
    try:
        _orig_makedirs(reports_dir, exist_ok=True)
        
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
                "requested_path": violated_path,
                "operation": operation,
                "allowed_paths": allowed_list
            },
            "instruction": (
                f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                f"attempted an unauthorized '{operation}' operation on '{violated_path}'. "
                f"Allowed paths: {allowed_list}. "
                f"Please update the code to access only authorized paths, or add exceptions in shield.yaml."
            )
        }
        
        report_path = os.path.join(reports_dir, "violation_report.json")
        with _orig_open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    finally:
        _local_state.set(False)
        
    is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
    if is_passive:
        print(f"Warning: agent-shield passive mode violation detected: Filesystem operation '{operation}' on '{violated_path}' is forbidden.")
    else:
        raise FilesystemViolationError(
            f"Function '{func.__name__ if func else 'unknown'}' attempted unauthorized '{operation}' to path '{violated_path}'."
        )

# Custom hook wrappers for standard library functions
def _custom_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        allow_read, allow_write, func, project_root = restricted
        path = str(file)
        
        # Check if the operation is a write operation
        is_write = any(char in mode for char in ('w', 'a', 'x', '+'))
        
        if is_write:
            if not _is_path_allowed(path, allow_write):
                _report_violation_and_raise(path, "write", allow_write, func, project_root)
        else:
            if not _is_path_allowed(path, allow_read):
                _report_violation_and_raise(path, "read", allow_read, func, project_root)
                
    return _orig_open(file, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline, closefd=closefd, opener=opener)

def _custom_remove(path, *, dir_fd=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(path), allow_write):
            _report_violation_and_raise(str(path), "remove", allow_write, func, project_root)
    return _orig_remove(path, dir_fd=dir_fd)

def _custom_unlink(path, *, dir_fd=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(path), allow_write):
            _report_violation_and_raise(str(path), "unlink", allow_write, func, project_root)
    return _orig_unlink(path, dir_fd=dir_fd)

def _custom_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(src), allow_write):
            _report_violation_and_raise(str(src), "rename_src", allow_write, func, project_root)
        if not _is_path_allowed(str(dst), allow_write):
            _report_violation_and_raise(str(dst), "rename_dst", allow_write, func, project_root)
    return _orig_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

def _custom_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(src), allow_write):
            _report_violation_and_raise(str(src), "replace_src", allow_write, func, project_root)
        if not _is_path_allowed(str(dst), allow_write):
            _report_violation_and_raise(str(dst), "replace_dst", allow_write, func, project_root)
    return _orig_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

def _custom_mkdir(path, mode=0o777, *, dir_fd=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(path), allow_write):
            _report_violation_and_raise(str(path), "mkdir", allow_write, func, project_root)
    return _orig_mkdir(path, mode=mode, dir_fd=dir_fd)

def _custom_makedirs(name, mode=0o777, exist_ok=False):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(name), allow_write):
            _report_violation_and_raise(str(name), "makedirs", allow_write, func, project_root)
    return _orig_makedirs(name, mode=mode, exist_ok=exist_ok)

def _custom_rmdir(path, *, dir_fd=None):
    restricted = _fs_restricted_context.get()
    if restricted and not _local_state.get():
        _, allow_write, func, project_root = restricted
        if not _is_path_allowed(str(path), allow_write):
            _report_violation_and_raise(str(path), "rmdir", allow_write, func, project_root)
    return _orig_rmdir(path, dir_fd=dir_fd)

# Apply global monkeypatches on import
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
    """Decorator to restrict filesystem access within the decorated function.
    
    Supported parameters:
    - allow_read: A list of allowed directory or file paths for reading.
    - allow_write: A list of allowed directory or file paths for writing/modifying.
    """
    if allow_read is None:
        allow_read = []
    if allow_write is None:
        allow_write = []
        
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                existing = _fs_restricted_context.get()
                if existing:
                    parent_read, parent_write = existing[0], existing[1]
                    new_read = list(set(allow_read).intersection(set(parent_read))) if allow_read is not None else parent_read
                    new_write = list(set(allow_write).intersection(set(parent_write))) if allow_write is not None else parent_write
                else:
                    new_read = allow_read
                    new_write = allow_write
                    
                token = _fs_restricted_context.set((new_read, new_write, func, project_root))
                try:
                    return await func(*args, **kwargs)
                finally:
                    _fs_restricted_context.reset(token)
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                existing = _fs_restricted_context.get()
                if existing:
                    parent_read, parent_write = existing[0], existing[1]
                    new_read = list(set(allow_read).intersection(set(parent_read))) if allow_read is not None else parent_read
                    new_write = list(set(allow_write).intersection(set(parent_write))) if allow_write is not None else parent_write
                else:
                    new_read = allow_read
                    new_write = allow_write
                    
                token = _fs_restricted_context.set((new_read, new_write, func, project_root))
                try:
                    return func(*args, **kwargs)
                finally:
                    _fs_restricted_context.reset(token)
            return wrapper
    return decorator
