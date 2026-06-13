import functools
import socket
import os
import inspect
import json
import contextvars
from agent_shield.contracts import NetworkViolationError, CallLimitViolationError

# Store original socket methods
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex

# Active thread/task restriction context
_restricted_context = contextvars.ContextVar("restricted_context", default=None)
# Active thread/task call limit context
_call_limit_context = contextvars.ContextVar("call_limit_context", default=None)

def _is_host_allowed(target_host: str, allowed_hosts: list[str]) -> bool:
    target_host = target_host.lower().strip()
    if target_host in allowed_hosts:
        return True
        
    for allowed in allowed_hosts:
        allowed = allowed.lower().strip()
        if allowed == "*":
            return True
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if target_host.endswith(suffix) or target_host == allowed[2:]:
                return True
                
    # Fallback to IP address resolution comparison
    try:
        target_ips = set()
        try:
            infos = socket.getaddrinfo(target_host, None)
            for info in infos:
                target_ips.add(info[4][0])
        except Exception:
            pass
            
        for allowed in allowed_hosts:
            allowed = allowed.lower().strip()
            try:
                allowed_infos = socket.getaddrinfo(allowed, None)
                for info in allowed_infos:
                    if info[4][0] in target_ips:
                        return True
            except Exception:
                pass
    except Exception:
        pass
        
    return False

def _check_call_limit(address):
    limit_info = _call_limit_context.get()
    if not limit_info:
        return

    max_calls = limit_info["max_calls"]
    domains = limit_info["domains"]
    func = limit_info["func"]
    project_root = limit_info["project_root"]

    if isinstance(address, tuple) and len(address) > 0:
        host = address[0]
        if _is_host_allowed(host, domains):
            limit_info["current_calls"] += 1
            current = limit_info["current_calls"]
            if current > max_calls:
                reports_dir = os.path.join(project_root, "shield_reports")
                os.makedirs(reports_dir, exist_ok=True)
                try:
                    func_file = inspect.getfile(func)
                    func_abs_file = os.path.abspath(func_file)
                except Exception:
                    func_abs_file = "unknown"
                report = {
                    "violation_type": "call_limit_violation",
                    "function_name": func.__name__,
                    "file_path": func_abs_file,
                    "details": {
                        "attempted_host": host,
                        "max_calls": max_calls,
                        "current_calls": current
                    },
                    "instruction": (
                        f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                        f"exceeded its API call limit of {max_calls} calls (current count: {current}). "
                        f"Please ensure the function is not stuck in an infinite loop."
                    )
                }
                report_path = os.path.join(reports_dir, "violation_report.json")
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                raise CallLimitViolationError(
                    f"Function '{func.__name__}' exceeded allowed API call limit of {max_calls}."
                )

def _custom_connect(self, address):
    _check_call_limit(address)
    restricted = _restricted_context.get()
    if restricted:
        allowed_hosts, func, project_root = restricted
        if isinstance(address, tuple) and len(address) > 0:
            host = address[0]
            if not _is_host_allowed(host, allowed_hosts):
                # Generate JSON report
                reports_dir = os.path.join(project_root, "shield_reports")
                os.makedirs(reports_dir, exist_ok=True)
                
                try:
                    func_file = inspect.getfile(func)
                    func_abs_file = os.path.abspath(func_file)
                except Exception:
                    func_abs_file = "unknown"
                    
                report = {
                    "violation_type": "network_violation",
                    "function_name": func.__name__,
                    "file_path": func_abs_file,
                    "details": {
                        "attempted_host": host,
                        "allowed_hosts": allowed_hosts
                    },
                    "instruction": (
                        f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                        f"attempted to establish an unauthorized network connection to '{host}'. "
                        f"Connections are restricted to: {', '.join(allowed_hosts)}. "
                        f"Please remove this network call or connect to an allowed host."
                    )
                }
                report_path = os.path.join(reports_dir, "violation_report.json")
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                
                raise NetworkViolationError(
                    f"Function '{func.__name__}' attempted unauthorized connection to host '{host}'."
                )
                
    return _orig_connect(self, address)

def _custom_connect_ex(self, address):
    _check_call_limit(address)
    restricted = _restricted_context.get()
    if restricted:
        allowed_hosts, func, project_root = restricted
        if isinstance(address, tuple) and len(address) > 0:
            host = address[0]
            if not _is_host_allowed(host, allowed_hosts):
                # Raise exception immediately for contract protection
                reports_dir = os.path.join(project_root, "shield_reports")
                os.makedirs(reports_dir, exist_ok=True)
                
                try:
                    func_file = inspect.getfile(func)
                    func_abs_file = os.path.abspath(func_file)
                except Exception:
                    func_abs_file = "unknown"
                    
                report = {
                    "violation_type": "network_violation",
                    "function_name": func.__name__,
                    "file_path": func_abs_file,
                    "details": {
                        "attempted_host": host,
                        "allowed_hosts": allowed_hosts
                    },
                    "instruction": (
                        f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                        f"attempted to establish an unauthorized network connection to '{host}'. "
                        f"Connections are restricted to: {', '.join(allowed_hosts)}. "
                        f"Please remove this network call or connect to an allowed host."
                    )
                }
                report_path = os.path.join(reports_dir, "violation_report.json")
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                
                raise NetworkViolationError(
                    f"Function '{func.__name__}' attempted unauthorized connection to host '{host}'."
                )
                
    return _orig_connect_ex(self, address)

# Apply global monkeypatch once upon import
socket.socket.connect = _custom_connect
socket.socket.connect_ex = _custom_connect_ex

def restrict_network(allowed_hosts: list[str]):
    """Decorator to restrict network connections established by a function.
    
    If the function attempts to connect to any host not in allowed_hosts,
    it raises a NetworkViolationError.
    """
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                existing = _restricted_context.get()
                if existing:
                    parent_hosts = existing[0]
                    new_hosts = list(set(allowed_hosts).intersection(set(parent_hosts)))
                else:
                    new_hosts = allowed_hosts
                    
                token = _restricted_context.set((new_hosts, func, project_root))
                try:
                    return await func(*args, **kwargs)
                finally:
                    _restricted_context.reset(token)
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                existing = _restricted_context.get()
                if existing:
                    parent_hosts = existing[0]
                    new_hosts = list(set(allowed_hosts).intersection(set(parent_hosts)))
                else:
                    new_hosts = allowed_hosts
                    
                token = _restricted_context.set((new_hosts, func, project_root))
                try:
                    return func(*args, **kwargs)
                finally:
                    _restricted_context.reset(token)
            return wrapper
    return decorator

def limit_calls(max_calls: int = 10, domains: list[str] = None):
    """Decorator to restrict the number of network connections established by a function.
    
    If the function attempts to connect to any domain matching domains more than max_calls times,
    it raises a CallLimitViolationError.
    """
    if domains is None:
        domains = ["*"]
        
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                token = _call_limit_context.set({
                    "max_calls": max_calls,
                    "current_calls": 0,
                    "domains": domains,
                    "func": func,
                    "project_root": project_root
                })
                try:
                    return await func(*args, **kwargs)
                finally:
                    _call_limit_context.reset(token)
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                token = _call_limit_context.set({
                    "max_calls": max_calls,
                    "current_calls": 0,
                    "domains": domains,
                    "func": func,
                    "project_root": project_root
                })
                try:
                    return func(*args, **kwargs)
                finally:
                    _call_limit_context.reset(token)
            return wrapper
    return decorator
