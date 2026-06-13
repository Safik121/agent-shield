from agent_shield.contracts import shield

class PaymentError(Exception):
    """Custom exception for payment processing errors."""
    pass


@shield(forbidden_imports=["os"])
def process_payment(amount: float) -> dict:
    """Simulates payment processing.
    
    This function deliberately violates coding guidelines for testing purposes:
    1. It imports a forbidden module inside the function scope.
    2. It violates its own type hint by returning a string instead of a dict.
    """
    import os  # Forbidden import inside function
    
    if amount <= 0:
        raise PaymentError("Amount must be greater than zero.")
        
    return "success"  # Returns string instead of dict
