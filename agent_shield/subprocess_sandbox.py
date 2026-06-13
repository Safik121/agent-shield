import functools
import threading
import subprocess
import os
import inspect
import json

# Active thread restriction registry: thread_id -> (allowed_commands, func, project_root)
_subprocess_restricted_threads = {}
_lock = threading.Lock()
_local_state = threading.local()

# Store original methods
_orig_Popen = subprocess.Popen
_orig_system = os.system
_orig_popen_os = os.popen

def _extract_commands(args, shell=False) -> list[str]:
    """Helper to extract command executable basenames from arguments."""
    commands = []
    if isinstance(args, (list, tuple)):
        if len(args) > 0:
            cmd = args[0]
            base = os.path.basename(str(cmd))
            commands.append(base)
    elif isinstance(args, (str, bytes)):
        args_str = args.decode("utf-8") if isinstance(args, bytes) else str(args)
        if not shell:
            words = args_str.split()
            if words:
                base = os.path.basename(words[0])
                commands.append(base)
        else:
            # shell=True: split by shell control operators
            import re
            parts = re.split(r'&&|\|\||;|\|', args_str)
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                words = part.split()
                if words:
                    base = os.path.basename(words[0])
                    commands.append(base)
    return commands

def _is_command_allowed(cmd: str, allowed: list[str]) -> bool:
    """Checks if a command executable is matched by any pattern in allowed list."""
    if not allowed:
        return False
    cmd = cmd.strip()
    for pattern in allowed:
        pattern = pattern.strip()
        if pattern == "*":
            return True
        import fnmatch
        if fnmatch.fnmatch(cmd, pattern):
            return True
    return False

def _report_and_raise(forbidden_cmd: str, full_cmd: str, allowed: list[str], func, project_root: str):
    reports_dir = os.path.join(project_root, "shield_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    details = {
        "forbidden_command": forbidden_cmd,
        "full_command": str(full_cmd),
        "allowed_commands": allowed
    }
    
    report = {
        "violation_type": "subprocess_violation",
        "function_name": func.__name__ if func else "unknown",
        "file_path": os.path.abspath(inspect.getfile(func)) if func else "unknown",
        "details": details,
        "instruction": f"Do not execute command '{forbidden_cmd}'. Allowed commands: {allowed}"
    }
    
    report_path = os.path.join(reports_dir, "violation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
    if is_passive:
        print(f"Warning: agent-shield passive mode violation detected: Tried to run forbidden command '{forbidden_cmd}'")
    else:
        from agent_shield.contracts import SubprocessViolationError
        raise SubprocessViolationError(f"Subprocess Sandbox: execution of '{forbidden_cmd}' is not allowed by whitelist {allowed}.")

# Custom Popen subclass
class _custom_Popen(_orig_Popen):
    def __init__(self, args, *args_rest, **kwargs):
        thread_id = threading.get_ident()
        with _lock:
            restricted = _subprocess_restricted_threads.get(thread_id)
            
        if restricted and not getattr(_local_state, "in_check", False):
            _local_state.in_check = True
            try:
                allowed, func, project_root = restricted
                executable = kwargs.get("executable")
                shell = kwargs.get("shell", False)
                
                cmds = []
                if executable:
                    cmds.append(os.path.basename(str(executable)))
                cmds.extend(_extract_commands(args, shell=shell))
                
                for cmd in cmds:
                    if not _is_command_allowed(cmd, allowed):
                        _report_and_raise(cmd, args, allowed, func, project_root)
            finally:
                _local_state.in_check = False
                
        super().__init__(args, *args_rest, **kwargs)

def _custom_system(command):
    thread_id = threading.get_ident()
    with _lock:
        restricted = _subprocess_restricted_threads.get(thread_id)
        
    if restricted and not getattr(_local_state, "in_check", False):
        _local_state.in_check = True
        try:
            allowed, func, project_root = restricted
            cmds = _extract_commands(str(command), shell=True)
            for cmd in cmds:
                if not _is_command_allowed(cmd, allowed):
                    _report_and_raise(cmd, command, allowed, func, project_root)
        finally:
            _local_state.in_check = False
            
    return _orig_system(command)

def _custom_popen_os(cmd, mode='r', buffering=-1):
    thread_id = threading.get_ident()
    with _lock:
        restricted = _subprocess_restricted_threads.get(thread_id)
        
    if restricted and not getattr(_local_state, "in_check", False):
        _local_state.in_check = True
        try:
            allowed, func, project_root = restricted
            cmds = _extract_commands(str(cmd), shell=True)
            for cmd_name in cmds:
                if not _is_command_allowed(cmd_name, allowed):
                    _report_and_raise(cmd_name, cmd, allowed, func, project_root)
        finally:
            _local_state.in_check = False
            
    return _orig_popen_os(cmd, mode=mode, buffering=buffering)

# Apply monkeypatching globally
subprocess.Popen = _custom_Popen
os.system = _custom_system
os.popen = _custom_popen_os

def restrict_subprocess(allow_commands: list[str] = None):
    """Decorator to restrict subprocess execution within the decorated function.
    
    Supported parameters:
    - allow_commands: A list of allowed command executables (e.g. ['git', 'ls']).
    """
    if allow_commands is None:
        allow_commands = []
        
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            thread_id = threading.get_ident()
            
            # Find project root
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            
            # Register active restriction for this thread
            with _lock:
                existing = _subprocess_restricted_threads.get(thread_id)
                if existing:
                    parent_allowed = existing[0]
                    # Compute intersection
                    new_allowed = list(set(allow_commands).intersection(set(parent_allowed)))
                else:
                    new_allowed = allow_commands
                
                _subprocess_restricted_threads[thread_id] = (new_allowed, func, project_root)
                
            try:
                return func(*args, **kwargs)
            finally:
                with _lock:
                    if existing:
                        _subprocess_restricted_threads[thread_id] = existing
                    else:
                        _subprocess_restricted_threads.pop(thread_id, None)
                        
        return wrapper
    return decorator
