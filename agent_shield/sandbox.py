import sys
import functools
import typing
from agent_shield.contracts import ShieldViolationError

def mock_only(func: typing.Callable) -> typing.Callable:
    """Decorator to enforce that a function is always mocked in test environments.
    
    If the function is executed directly in a test environment (e.g., pytest or unittest
    are present in sys.modules), raises ShieldViolationError. Otherwise, executes normally.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if "pytest" in sys.modules or "unittest" in sys.modules:
            raise ShieldViolationError(
                f"Function '{func.__name__}' is marked @mock_only but was executed directly in a test environment without a mock."
            )
        return func(*args, **kwargs)
    return wrapper
