# Agent-Safeguard

A lightweight, enterprise-grade runtime sandboxing and definition-time guardrail framework for Python applications, built to safely run code generated or modified by AI agents.

📖 **Full Documentation**: **[shield-docs-mu.vercel.app](https://shield-docs-mu.vercel.app)**

---

## Why Agent-Safeguard?

AI coding agents are excellent at generating code but often lack a global understanding of architectural boundaries, leading to path traversal bypasses, illegal imports, API resource leaks, or infinite lockups. 

Agent-Safeguard captures these boundary violations, blocks them in real-time, and generates **structured JSON diagnostic reports** (`shield_reports/violation_report.json`) that AI agents can ingest to automatically self-correct and rewrite their code!

## Core Protection Areas

* **Architectural Integrity (AST)**: `@shield`, `@freeze`, and `@lock_signature` to scan imports, prevent code mutations, and secure API parameters.
* **Security & Resource Sandboxing**: `@restrict_network`, `@restrict_fs`, `@virtual_fs` (redirecting all writes to RAM), database locks, and memory/timeout limits.
* **AI & Prompt Guidelines**: `@prompt_inject` (docstring constraints) and `@prompt_assert` (Gemini-powered semantic assertions).
* **Central Policy Injection**: Define rules globally in a central `shield.yaml` to prevent agents from simply deleting Python decorators from source files.

## Installation

```bash
pip install agent-safeguard
```

Import it in your Python code using the underscore name `agent_shield`:
```python
from agent_shield import shield, virtual_fs, restrict_db
```

## Quick Start Example

1. Create a `shield.yaml` rule file in your project root:
```yaml
rules:
  - pattern: "sandbox_code.*"
    timeout: 0.5
    virtual_fs: true
    restrict_network: ["api.stripe.com"]
```

2. Run your functions normally; Agent-Safeguard will automatically enforce limits and write JSON reports on violation:
```python
# sandbox_code.py
import urllib.request

def process_data():
    # Attempting to fetch unauthorized API will block and generate a violation report
    response = urllib.request.urlopen("https://unauthorized-api.com")
    return response.read()
```

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
