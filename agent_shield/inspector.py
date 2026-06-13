import ast
import inspect
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
