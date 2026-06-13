import functools
import os
import inspect
import json
from agent_shield.contracts import PromptInjectionViolationError

DEFAULT_INJECTION_SIGNATURES = [
    "ignore previous instructions",
    "ignore all previous",
    "ignore the above",
    "system override",
    "developer mode",
    "bypass safety",
    "you must now",
    "new instruction",
    "ignore safety",
    "prompt injection"
]


def _scan_value(val, rules, seen=None):
    if seen is None:
        seen = set()
        
    val_id = id(val)
    if val_id in seen:
        return None
        
    if isinstance(val, str):
        val_lower = val.lower()
        for rule in rules:
            if rule.lower() in val_lower:
                return rule
    elif isinstance(val, (list, tuple, set)):
        seen.add(val_id)
        for item in val:
            res = _scan_value(item, rules, seen)
            if res:
                return res
    elif isinstance(val, dict):
        seen.add(val_id)
        for k, v in val.items():
            res = _scan_value(k, rules, seen)
            if res:
                return res
            res = _scan_value(v, rules, seen)
            if res:
                return res
    return None


def _report_injection_and_raise(matched_sig, value, source, func, project_root):
    reports_dir = os.path.join(project_root, "shield_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    try:
        func_file = inspect.getfile(func)
        func_abs_file = os.path.abspath(func_file)
    except Exception:
        func_abs_file = "unknown"
        
    report = {
        "violation_type": "prompt_injection_violation",
        "function_name": func.__name__,
        "file_path": func_abs_file,
        "details": {
            "matched_signature": matched_sig,
            "detected_in": source,
            "value_snippet": str(value)[:500]
        },
        "instruction": (
            f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
            f"received/returned a payload containing a prompt injection attempt matching: '{matched_sig}'. "
            f"Execution has been blocked to maintain security alignment."
        )
    }
    
    report_path = os.path.join(reports_dir, "violation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    raise PromptInjectionViolationError(
        f"Prompt Guard: Blocked execution due to detected prompt injection signature '{matched_sig}'."
    )


def guard_prompt(scan_input: bool = True, scan_output: bool = False, custom_rules: list[str] = None):
    """Decorator to scan function arguments and return values for prompt injection signatures."""
    rules = custom_rules if custom_rules is not None else DEFAULT_INJECTION_SIGNATURES
    
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                if scan_input:
                    # Scan args
                    matched = _scan_value(args, rules)
                    if matched:
                        _report_injection_and_raise(matched, args, "input_arguments", func, project_root)
                    # Scan kwargs
                    matched = _scan_value(kwargs, rules)
                    if matched:
                        _report_injection_and_raise(matched, kwargs, "input_arguments", func, project_root)
                        
                result = await func(*args, **kwargs)
                
                if scan_output:
                    matched = _scan_value(result, rules)
                    if matched:
                        _report_injection_and_raise(matched, result, "returned_value", func, project_root)
                        
                return result
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                if scan_input:
                    # Scan args
                    matched = _scan_value(args, rules)
                    if matched:
                        _report_injection_and_raise(matched, args, "input_arguments", func, project_root)
                    # Scan kwargs
                    matched = _scan_value(kwargs, rules)
                    if matched:
                        _report_injection_and_raise(matched, kwargs, "input_arguments", func, project_root)
                        
                result = func(*args, **kwargs)
                
                if scan_output:
                    matched = _scan_value(result, rules)
                    if matched:
                        _report_injection_and_raise(matched, result, "returned_value", func, project_root)
                        
                return result
            return wrapper
    return decorator
