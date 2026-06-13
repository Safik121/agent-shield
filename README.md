# Agent-Safeguard

A lightweight, enterprise-grade architectural guardrail and sandbox library for Python applications developed in collaboration with AI agents.

---

## The Problem

AI coding assistants (such as Antigravity, Cursor, Copilot, and Codex) excel at generating localized code but operate within limited context windows. Consequently, they lack a comprehensive understanding of global architectural boundaries. Autonomous modifications frequently bypass type contracts, introduce illegal imports, violate filesystem/network access policies, or create infinite resource lockups.

## The Solution

**Agent-Safeguard** establishes programmatic guardrails that enforce structural and runtime invariants. By combining definition-time AST checks, dynamic socket/file monkeypatching, RAM/CPU constraints, database access filters, and prompt injection guards, it captures boundary violations immediately. 

Crucially, instead of raising generic stack traces, Agent-Safeguard generates **structured JSON reports** designed to be ingested by LLM agents, enabling closed-loop, automated self-correction.

---

## Installation

Install using pip:
```bash
pip install agent-safeguard
```

Import it in your Python code using `agent_shield`:
```python
from agent_shield import virtual_fs, guard_prompt
```

---

## Core Features & Decorators

### 1. Advanced Sandboxes & Guardrails

*   **`@virtual_fs(in_memory_write=True, allow_real_read=None)`**
    Redirects filesystem writes to an in-memory virtual storage in RAM. Filesystem reads check the virtual state first, falling back to the real disk if the path is whitelisted in `allow_real_read` (defaults to permitting all reads but redirecting all writes to RAM, perfect for safe dry-runs).
    
*   **`@guard_prompt(scan_input=True, scan_output=False, custom_rules=None)`**
    Scans function inputs and outputs for prompt injection and developer mode override signatures (e.g. `"ignore previous instructions"`, `"system override"`, `"bypass safety"`). Raises `PromptInjectionViolationError` on match.
    
*   **`@restrict_db(read_only=True)`**
    Intercepts `sqlite3` database connections and restricts execution to read-only queries. If a query contains write/alter keywords (e.g. `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`), blocks it and raises `DatabaseViolationError`.

*   **`@restrict_env(allow_mutation=False)`**
    Prevents modifying or deleting system environment variables (`os.environ`) during function execution, raising `EnvironmentViolationError`.

### 2. Architectural Integrity & AST Checks

*   **`@shield(allowed_imports=..., forbidden_imports=..., allow_unsafe=False, allow_globals=False, max_complexity=None)`**
    Enforces function boundary constraints at definition time via static AST analysis:
    *   **Allowed Imports**: Whitelist only specific modules for import inside the function.
    *   **Forbidden Imports**: Blacklist specific modules (e.g. blocking `os` or `sys`).
    *   **Unsafe Execution**: Blocks calls to `eval()` and `exec()`.
    *   **Globals Usage**: Blocks the `global` keyword to prevent global state pollution.
    *   **Hardcoded Secrets**: Scans constants for API keys (e.g., AWS, OpenAI) or variables named `api_key`/`secret`.
    *   **CPU Lockups**: Detects infinite loops with empty bodies (`while True: pass`).
    *   **Complexity limit**: Restricts the maximum allowed cyclomatic complexity of the function's AST.
    *   **Runtime Types**: Automatically validates function return values against declared type hints (supports generics and union types).

*   **`@freeze`**
    Locks the function source code. Registers a cryptographic SHA-256 hash of the function implementation inside `shield_reports/frozen_functions.json`. Any unauthorized modifications to the code body will raise a `ShieldViolationError` on startup.

*   **`@lock_signature`**
    Locks the function's signature. Saves parameter names, ordering, defaults, and type hints in `shield_reports/locked_signatures.json` to prevent AI from altering the function interface.

### 3. Resource & Security Sandboxing

*   **`@timeout(seconds: float)`**
    Enforces a strict runtime execution time limit. Bypasses signal limits gracefully when executed in background threads. Raises `TimeoutViolationError` if exceeded.

*   **`@limit_memory(max_mb: float)`**
    Monitors RSS memory growth of the process during execution. If the memory delta exceeds the specified limit, injects `MemoryViolationError` into the main thread.

*   **`@restrict_network(allowed_hosts: list[str])`**
    Restricts socket-level connections. Monkeypatches `socket.connect` dynamically and thread-safely. Supports wildcards (e.g. `*.stripe.com`) and resolves domain IPs automatically.

*   **`@restrict_fs(allow_read: list[str] = None, allow_write: list[str] = None)`**
    Monkeypatches `builtins.open` and standard file manipulation operations. Prevents path traversal bypasses and whitelists Python interpreter/import folders so package loading remains unimpeded.

*   **`@no_side_effects(allow_args_mutation=False, allow_globals=False, allow_stdout=False)`**
    Enforces function purity. Verifies that the function does not mutate its arguments, modify module-level globals, or print output to the console. Raises `SideEffectViolationError` on violation.

### 4. AI Directives & Semantic Assertions

*   **`@prompt_inject(instruction: str)`**
    Prepend a standardized, high-visibility block containing architectural instructions directly to the function's docstring:
    ```
    === AI ASSISTANT ARCHITECTURAL CONSTRAINT ===
    {instruction}
    =============================================
    ```

*   **`@prompt_assert(prompt: str)`**
    Sends the function source code to the Gemini API (`gemini-1.5-flash`) at definition time to semantically evaluate whether the implementation satisfies the natural language prompt constraint. Supports registry mocking for offline unit testing.

---

### 5. Centrally Configured Guardrails (`shield.yaml`)

To prevent AI agents from editing or deleting decorators from Python files, you can define your project rules centrally inside a `shield.yaml` file on the project root:

```yaml
rules:
  - pattern: "my_app.payments.*"
    timeout: 5.0
    restrict_network: ["api.stripe.com"]
    virtual_fs: true
    guard_prompt: true
    restrict_db: true
  - pattern: "my_app.utils.*"
    allowed_imports: ["math", "json"]
```

Agent-Safeguard hooks into Python's import system (`builtins.__import__`) and automatically decorates all matching module functions at import time.

### 6. Audit Mode (Passive Mode)

Set the environment variable `AGENT_SHIELD_PASSIVE=true` to enable passive auditing. Under passive mode, rules write structured JSON reports and output console warnings on violations, but **do not raise exceptions** (excluding interruptive constraints like timeout).

---

## JSON Diagnostic Reports

When a constraint is violated, Agent-Safeguard writes a diagnostic report to `shield_reports/violation_report.json`:

```json
{
  "violation_type": "network_violation",
  "function_name": "charge_customer",
  "file_path": "/Users/safik/PycharmProjects/agent-shield/my_app/payments.py",
  "details": {
    "attempted_host": "unauthorized-api.com",
    "allowed_hosts": ["api.stripe.com"]
  },
  "instruction": "AI Assistant Instruction: The function 'charge_customer' in file '/Users/safik/PycharmProjects/agent-shield/my_app/payments.py' attempted to establish an unauthorized network connection to 'unauthorized-api.com'. Connections are restricted to: api.stripe.com. Please remove this network call or connect to an allowed host."
}
```

AI agents can read this file in a self-correction loop to rewrite their code automatically.

---

## Quick Start

Create a `shield.yaml` in your project root:
```yaml
rules:
  - pattern: "sandbox_code.*"
    timeout: 0.1
    allow_read: ["/tmp"]
```

Define your functions, and Agent-Safeguard handles the rest:
```python
# sandbox_code.py
def process_data():
    # Attempting to read unauthorized file will trigger FileSystemViolationError
    with open("/etc/passwd", "r") as f:
        return f.read()
```

---

## License

This project is licensed under the Apache License 2.0.
