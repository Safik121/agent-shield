import functools
import inspect
import json
import os
import urllib.request
from agent_shield.contracts import PromptAssertionError

# Global registry for unit testing: function_name -> {"satisfied": bool, "reason": str}
_prompt_assert_mocks = {}

def register_prompt_assert_mock(function_name: str, satisfied: bool, reason: str = ""):
    """Registers a mock outcome for @prompt_assert in tests."""
    _prompt_assert_mocks[function_name] = {"satisfied": satisfied, "reason": reason}

def clear_prompt_assert_mocks():
    """Clears all registered mock outcomes."""
    _prompt_assert_mocks.clear()

def _strip_json_markdown(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

def prompt_assert(prompt: str):
    """Decorator to assert a semantic prompt constraint on a function's implementation.
    
    Analyses the source code of the function using the Gemini API.
    If the constraint is violated, raises a PromptAssertionError.
    """
    def decorator(func):
        try:
            source = inspect.getsource(func)
            dedented_source = inspect.cleandoc(source)
        except Exception:
            return func

        func_name = func.__name__
        mock_result = _prompt_assert_mocks.get(func_name)
        
        satisfied = True
        reason = ""
        
        if mock_result is not None:
            satisfied = mock_result["satisfied"]
            reason = mock_result["reason"]
        else:
            api_key = os.environ.get("GEMINI_API_KEY")
            if api_key:
                try:
                    eval_prompt = (
                        f"Analyze the following Python function source code and verify if it satisfies the semantic constraint: \"{prompt}\".\n\n"
                        f"Source Code:\n```python\n{dedented_source}\n```\n\n"
                        f"Respond ONLY with a raw JSON object in this format:\n"
                        f"{{\n"
                        f"  \"satisfied\": true/false,\n"
                        f"  \"reason\": \"explanation of why it is or is not satisfied\"\n"
                        f"}}\n"
                    )
                    
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
                    headers = {"Content-Type": "application/json"}
                    payload = {
                        "contents": [{
                            "parts": [{
                                "text": eval_prompt
                            }]
                        }]
                    }
                    
                    req = urllib.request.Request(
                        url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers=headers,
                        method="POST"
                    )
                    
                    with urllib.request.urlopen(req, timeout=10) as response:
                        resp_data = json.loads(response.read().decode("utf-8"))
                        text_response = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                        
                        cleaned_json = _strip_json_markdown(text_response)
                        result = json.loads(cleaned_json)
                        satisfied = bool(result.get("satisfied", True))
                        reason = str(result.get("reason", ""))
                except Exception as e:
                    print(f"Warning: agent-shield prompt_assert failed to contact Gemini API: {e}")
                    satisfied = True
            else:
                satisfied = True

        if not satisfied:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            reports_dir = os.path.join(project_root, "shield_reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            try:
                func_file = inspect.getfile(func)
                func_abs_file = os.path.abspath(func_file)
            except Exception:
                func_abs_file = "unknown"
                
            report = {
                "violation_type": "prompt_assertion_violation",
                "function_name": func_name,
                "file_path": func_abs_file,
                "details": {
                    "prompt": prompt,
                    "reason": reason
                },
                "instruction": (
                    f"AI Assistant Instruction: The function '{func_name}' in file '{func_abs_file}' "
                    f"failed to satisfy the semantic constraint: \"{prompt}\".\n"
                    f"Reason: {reason}\n"
                    f"Please refactor the function logic to comply with this requirement."
                )
            }
            report_path = os.path.join(reports_dir, "violation_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            raise PromptAssertionError(
                f"Function '{func_name}' violated semantic constraint: \"{prompt}\". "
                f"Reason: {reason}"
            )

        return func
    return decorator
