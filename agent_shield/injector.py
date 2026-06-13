import functools
import typing

def prompt_inject(instruction: str):
    """Decorator to inject high-visibility constraints into a function's docstring.
    
    This ensures that when an AI assistant retrieves the source or docstring of the function,
    it receives explicit guidelines or instructions on how to treat the code.
    """
    def decorator(func: typing.Callable) -> typing.Callable:
        header = "=== AI ASSISTANT ARCHITECTURAL CONSTRAINT ==="
        footer = "============================================="
        block = f"{header}\n{instruction}\n{footer}"
        
        # Modify the target function's docstring
        old_doc = func.__doc__
        if old_doc:
            func.__doc__ = f"{block}\n\n{old_doc}"
        else:
            func.__doc__ = block
            
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
            
        return wrapper
    return decorator
