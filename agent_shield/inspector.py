import ast
import inspect
import re
import textwrap
import typing

def find_forbidden_imports(func: typing.Callable, forbidden_modules: list[str]) -> list[str]:
    """Analyzes the Abstract Syntax Tree (AST) of a function to detect forbidden imports.
    
    Args:
        func: The function to analyze.
        forbidden_modules: A list of module names that are forbidden (e.g. ['os', 'sys']).
        
    Returns:
        A list of forbidden module names that were imported inside the function.
    """
    if not forbidden_modules:
        return []
        
    try:
        source = inspect.getsource(func)
        dedented_source = textwrap.dedent(source)
        tree = ast.parse(dedented_source)
    except Exception:
        # Gracefully handle dynamic functions or environments where source isn't available
        return []

    found_forbidden: set[str] = set()

    def is_forbidden(module_name: str) -> bool:
        if not module_name:
            return False
        parts = module_name.split('.')
        prefix = ""
        for part in parts:
            prefix = f"{prefix}.{part}" if prefix else part
            if prefix in forbidden_modules:
                return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if is_forbidden(alias.name):
                    for forbidden in forbidden_modules:
                        if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                            found_forbidden.add(forbidden)
        elif isinstance(node, ast.ImportFrom):
            if node.module and is_forbidden(node.module):
                for forbidden in forbidden_modules:
                    if node.module == forbidden or node.module.startswith(forbidden + "."):
                        found_forbidden.add(forbidden)

    return sorted(list(found_forbidden))


def detect_dangerous_functions(func: typing.Callable) -> list[str]:
    """Analyzes the AST of a function to detect calls to eval or exec.
    
    Args:
        func: The function to analyze.
        
    Returns:
        A list of dangerous function names ('eval', 'exec') called inside the function.
    """
    try:
        source = inspect.getsource(func)
        dedented_source = textwrap.dedent(source)
        tree = ast.parse(dedented_source)
    except Exception:
        return []

    dangerous_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                dangerous_calls.add(node.func.id)
                
    return sorted(list(dangerous_calls))


def detect_global_keyword(func: typing.Callable) -> bool:
    """Analyzes the AST of a function to detect the use of the global keyword.
    
    Args:
        func: The function to analyze.
        
    Returns:
        True if the 'global' keyword is used inside the function, False otherwise.
    """
    try:
        source = inspect.getsource(func)
        dedented_source = textwrap.dedent(source)
        tree = ast.parse(dedented_source)
    except Exception:
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            return True
            
    return False


# Regex patterns for standalone key identification
SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9\-]{32,70}"),  # OpenAI (sk-proj-... or sk-...)
    re.compile(r"AKIA[0-9A-Z]{16}"),       # AWS Access Key ID
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE) # Bearer token
]

SUSPICIOUS_VAR_NAMES = {"api_key", "secret", "password", "token", "passwd", "access_key", "secret_key", "pwd", "key"}


def detect_hardcoded_secrets(func: typing.Callable) -> list[str]:
    """Analyzes the AST of a function to detect potentially hardcoded API keys or secrets.
    
    Args:
        func: The function to analyze.
        
    Returns:
        A list of detected secret strings.
    """
    try:
        source = inspect.getsource(func)
        dedented_source = textwrap.dedent(source)
        tree = ast.parse(dedented_source)
    except Exception:
        return []

    detected_secrets = set()

    for node in ast.walk(tree):
        # Check variable assignment values
        if isinstance(node, ast.Assign):
            is_suspicious_var = False
            for target in node.targets:
                if isinstance(target, ast.Name) and any(susp_name in target.id.lower() for susp_name in SUSPICIOUS_VAR_NAMES):
                    is_suspicious_var = True
                    break
            if is_suspicious_var and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value.strip()
                placeholders = {"placeholder", "todo", "change_me", "my_key", "dummy", "test", "root", "secret", ""}
                if len(val) > 6 and val.lower() not in placeholders:
                    detected_secrets.add(node.value.value)
                    
        # Check all string constants against signature regexes
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            for pattern in SECRET_PATTERNS:
                if pattern.search(val):
                    detected_secrets.add(val)
                    break

    return sorted(list(detected_secrets))


def detect_cpu_lockups(func: typing.Callable) -> bool:
    """Analyzes the AST of a function to detect potential infinite loops causing CPU lockups.
    
    Args:
        func: The function to analyze.
        
    Returns:
        True if a dangerous CPU lockup pattern is found, False otherwise.
    """
    try:
        source = inspect.getsource(func)
        dedented_source = textwrap.dedent(source)
        tree = ast.parse(dedented_source)
    except Exception:
        return False

    def is_constant_truthy(test_node) -> bool:
        if isinstance(test_node, ast.Constant):
            return bool(test_node.value)
        if isinstance(test_node, ast.Name) and test_node.id == "True":
            return True
        return False

    def is_dangerous_body(body) -> bool:
        if not body:
            return True
        for stmt in body:
            if isinstance(stmt, ast.Pass):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue
            return False
        return True

    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            if is_constant_truthy(node.test) and is_dangerous_body(node.body):
                return True
                
    return False

