from agent_shield.contracts import shield, ShieldViolationError

class PaymentError(Exception):
    """Custom exception for payment processing errors."""
    pass


def run_demo():
    print("Defining process_payment function with forbidden_imports=['os']...")
    
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

    # If definition-time check passes, execute function to trigger runtime type contract
    print("Running process_payment(100.0)...")
    process_payment(100.0)


if __name__ == "__main__":
    try:
        run_demo()
    except ShieldViolationError as e:
        print("Agent-Shield successfully caught architectural violation!")
        print(f"Error details: {e}")
        print("JSON report was successfully generated in shield_reports/ directory.")

