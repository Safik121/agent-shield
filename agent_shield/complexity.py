import ast
import inspect
import textwrap

def calculate_cyclomatic_complexity(func) -> int:
    """Calculates the cyclomatic complexity of a function using AST analysis.
    
    Base complexity is 1. Decision points (If, For, While, ExceptHandler, BoolOp, IfExp, Comprehensions)
    increment the complexity by 1.
    """
    try:
        source = inspect.getsource(func)
        dedented_source = textwrap.dedent(source)
        tree = ast.parse(dedented_source)
    except Exception:
        return 1

    complexity = 1

    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.IfExp)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
            complexity += 1

    return complexity
