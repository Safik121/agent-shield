import functools
import threading
import ctypes
import os
import sys
import subprocess
import inspect
import json
import time
from agent_shield.contracts import MemoryViolationError

def get_memory_usage_kb() -> int:
    """Gets the resident set size (RSS) memory usage of the current process in kilobytes."""
    try:
        if sys.platform != "win32":
            pid = os.getpid()
            output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], stderr=subprocess.DEVNULL)
            return int(output.strip())
        else:
            pid = os.getpid()
            output = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            parts = output.strip().split(",")
            if len(parts) >= 5:
                mem_str = parts[4].strip('"').replace(" K", "").replace(",", "").replace(" ", "")
                return int(mem_str)
            return 0
    except Exception:
        return 0

def limit_memory(max_mb: float):
    """Decorator to enforce a memory usage limit on a function.
    
    If the function's memory usage (RSS increase) exceeds max_mb during execution,
    raises a MemoryViolationError.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            initial_mem = get_memory_usage_kb()
            limit_kb = int(max_mb * 1024)
            
            if initial_mem <= 0:
                return func(*args, **kwargs)

            main_thread_id = threading.get_ident()
            stop_event = threading.Event()
            monitor_state = {"exceeded": False, "max_allocated_kb": 0}

            def monitor():
                while not stop_event.is_set():
                    current_mem = get_memory_usage_kb()
                    if current_mem > 0:
                        allocated = current_mem - initial_mem
                        if allocated > monitor_state["max_allocated_kb"]:
                            monitor_state["max_allocated_kb"] = allocated
                        
                        if allocated > limit_kb:
                            monitor_state["exceeded"] = True
                            ctypes.pythonapi.PyThreadState_SetAsyncExc(
                                ctypes.c_long(main_thread_id),
                                ctypes.py_object(MemoryViolationError)
                            )
                            break
                    time.sleep(0.05)

            monitor_thread = threading.Thread(target=monitor)
            monitor_thread.daemon = True
            monitor_thread.start()

            try:
                return func(*args, **kwargs)
            except MemoryViolationError:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                reports_dir = os.path.join(project_root, "shield_reports")
                
                try:
                    func_file = inspect.getfile(func)
                    func_abs_file = os.path.abspath(func_file)
                except Exception:
                    func_abs_file = "unknown"
                
                os.makedirs(reports_dir, exist_ok=True)
                report = {
                    "violation_type": "memory_limit_exceeded",
                    "function_name": func.__name__,
                    "file_path": func_abs_file,
                    "details": {
                        "memory_allocated_kb": monitor_state["max_allocated_kb"],
                        "limit_kb": limit_kb
                    },
                    "instruction": (
                        f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
                        f"exceeded its memory limit of {max_mb} MB (allocated: {monitor_state['max_allocated_kb'] / 1024:.2f} MB). "
                        f"Please optimize the memory usage of this function."
                    )
                }
                report_path = os.path.join(reports_dir, "violation_report.json")
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                
                raise MemoryViolationError(
                    f"Function '{func.__name__}' exceeded memory limit of {max_mb} MB "
                    f"(allocated: {monitor_state['max_allocated_kb'] / 1024:.2f} MB)."
                )
            finally:
                stop_event.set()
                monitor_thread.join(timeout=1.0)
                if not monitor_state["exceeded"]:
                    ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(main_thread_id), None)
                    
        return wrapper
    return decorator
