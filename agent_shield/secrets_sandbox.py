import functools
import threading
import socket
import sys
import os
import builtins
import inspect
import json
import re

# Active thread leak registry: thread_id -> (project_root, func, leak_types)
_leak_restricted_threads = {}
_lock = threading.Lock()
_local_state = threading.local()

# Original methods
_orig_send = socket.socket.send
_orig_sendall = socket.socket.sendall
_orig_open = builtins.open
_orig_stdout_write = sys.stdout.write
_orig_stderr_write = sys.stderr.write

class _WrappedFile:
    def __init__(self, orig_file, thread_id):
        self._orig_file = orig_file
        self._thread_id = thread_id
        
    def write(self, data):
        _check_payload_leak(self._thread_id, data, "filesystem_write")
        return self._orig_file.write(data)
        
    def writelines(self, lines):
        for line in lines:
            _check_payload_leak(self._thread_id, line, "filesystem_write")
        return self._orig_file.writelines(lines)
        
    def __getattr__(self, name):
        return getattr(self._orig_file, name)
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._orig_file.__exit__(exc_type, exc_val, exc_tb)

def _check_payload_leak(thread_id, data, source_type):
    if getattr(_local_state, "in_check", False):
        return
        
    with _lock:
        restricted = _leak_restricted_threads.get(thread_id)
    if not restricted:
        return
        
    if not data:
        return
        
    _local_state.in_check = True
    try:
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                text = str(data)
        else:
            text = str(data)
            
        # Truncate text if it is extremely large to prevent high CPU/memory usage
        MAX_SCAN_LEN = 2000000  # 2 MB limit
        if len(text) > MAX_SCAN_LEN:
            text = text[:1000000] + "\n[TRUNCATED]\n" + text[-1000000:]
            
        project_root, func, leak_types = restricted
        
        matched = None
        reason = None
        
        if "secrets" in leak_types:
            # Pre-check if any expected key prefix is present
            if any(prefix in text for prefix in ("AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "A3T", "sk-", "AIza")):
                # AWS Access Keys
                aws_match = re.search(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', text)
                if aws_match:
                    matched = aws_match.group(0)
                    reason = "AWS Access Key"
                else:
                    # OpenAI Keys
                    openai_match = re.search(r'sk-[a-zA-Z0-9]{20,}', text)
                    if openai_match:
                        matched = openai_match.group(0)
                        reason = "OpenAI API Key"
                    else:
                        # Google API Keys
                        google_match = re.search(r'AIza[0-9A-Za-z-_]{35}', text)
                        if google_match:
                            matched = google_match.group(0)
                            reason = "Google API Key"
                            
        if not matched and "pii" in leak_types:
            # Pre-check if "@" is present in text before running the email regex
            if "@" in text:
                # Email Address Pattern
                email_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
                if email_match:
                    matched = email_match.group(0)
                    reason = "Email Address"
                
        if matched:
            _report_leak_and_raise(reason, matched, source_type, func, project_root)
    finally:
        _local_state.in_check = False

def _report_leak_and_raise(leak_type: str, matched_val: str, source_type: str, func, project_root: str):
    masked_val = matched_val[:4] + "..." + matched_val[-4:] if len(matched_val) > 8 else "..."
    
    reports_dir = os.path.join(project_root, "shield_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    details = {
        "leak_type": leak_type,
        "masked_value": masked_val,
        "source": source_type
    }
    
    report = {
        "violation_type": "secrets_leak_violation",
        "function_name": func.__name__ if func else "unknown",
        "file_path": os.path.abspath(inspect.getfile(func)) if func else "unknown",
        "details": details,
        "instruction": f"Do not output sensitive {leak_type} to {source_type}."
    }
    
    report_path = os.path.join(reports_dir, "violation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    is_passive = os.environ.get("AGENT_SHIELD_PASSIVE", "").lower() in ("true", "1")
    if is_passive:
        print(f"Warning: agent-shield passive mode leak detected: {leak_type} in {source_type}")
    else:
        from agent_shield.contracts import SecretsLeakViolationError
        raise SecretsLeakViolationError(
            f"Secrets Sandbox: Blocked transmission of {leak_type} ({masked_val}) via {source_type}."
        )

# Wrapped custom methods
def _custom_send(self, data, flags=0):
    thread_id = threading.get_ident()
    _check_payload_leak(thread_id, data, "network_send")
    return _orig_send(self, data, flags)

def _custom_sendall(self, data, flags=0):
    thread_id = threading.get_ident()
    _check_payload_leak(thread_id, data, "network_send")
    return _orig_sendall(self, data, flags)

def _custom_open_leak(file, mode='r', *args, **kwargs):
    orig_file = _orig_open(file, mode, *args, **kwargs)
    thread_id = threading.get_ident()
    with _lock:
        restricted = _leak_restricted_threads.get(thread_id)
    if restricted:
        is_write = any(c in mode for c in ('w', 'a', 'x', '+'))
        if is_write:
            return _WrappedFile(orig_file, thread_id)
    return orig_file

def _custom_stdout_write(data):
    thread_id = threading.get_ident()
    _check_payload_leak(thread_id, data, "stdout_write")
    return _orig_stdout_write(data)

def _custom_stderr_write(data):
    thread_id = threading.get_ident()
    _check_payload_leak(thread_id, data, "stderr_write")
    return _orig_stderr_write(data)

# Apply global monkeypatching
socket.socket.send = _custom_send
socket.socket.sendall = _custom_sendall
builtins.open = _custom_open_leak
sys.stdout.write = _custom_stdout_write
sys.stderr.write = _custom_stderr_write

def no_secrets_leak(leak_types: list[str] = None):
    """Decorator to scan output streams (files, network, stdout) for secret/PII leaks.
    
    Supported leak_types:
    - 'secrets': detects AWS keys, Google API keys, OpenAI keys.
    - 'pii': detects email addresses.
    
    Defaults to both.
    """
    if leak_types is None:
        leak_types = ["secrets", "pii"]
        
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            thread_id = threading.get_ident()
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            
            with _lock:
                existing = _leak_restricted_threads.get(thread_id)
                _leak_restricted_threads[thread_id] = (project_root, func, leak_types)
                
            try:
                return func(*args, **kwargs)
            finally:
                with _lock:
                    if existing:
                        _leak_restricted_threads[thread_id] = existing
                    else:
                        _leak_restricted_threads.pop(thread_id, None)
        return wrapper
    return decorator
