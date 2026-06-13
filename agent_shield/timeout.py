import functools
import signal
from agent_shield.contracts import TimeoutViolationError

def timeout(seconds: float):
    """Decorator to enforce a runtime execution timeout on a function.
    
    If the function takes longer than the specified seconds, raising a TimeoutViolationError.
    If executed outside the main thread, the signal mechanism is bypassed gracefully.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def handler(signum, frame):
                raise TimeoutViolationError(f"Function '{func.__name__}' execution timed out after {seconds} seconds.")

            old_handler = None
            timer_set = False
            try:
                old_handler = signal.signal(signal.SIGALRM, handler)
                if hasattr(signal, "setitimer"):
                    signal.setitimer(signal.ITIMER_REAL, seconds)
                else:
                    signal.alarm(max(1, int(seconds)))
                timer_set = True
            except (ValueError, AttributeError):
                # signal mechanism is bypassed in non-main threads or unsupported systems
                pass

            try:
                return func(*args, **kwargs)
            finally:
                if timer_set:
                    try:
                        if hasattr(signal, "setitimer"):
                            signal.setitimer(signal.ITIMER_REAL, 0)
                        else:
                            signal.alarm(0)
                        if old_handler is not None:
                            signal.signal(signal.SIGALRM, old_handler)
                    except (ValueError, AttributeError):
                        pass
        return wrapper
    return decorator
