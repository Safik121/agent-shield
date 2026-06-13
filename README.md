# Agent-Shield

A lightweight architectural guardrail and contract enforcement library for Python applications developed by AI agents.

## The Problem

AI-driven software development agents have demonstrated remarkable capabilities in generating localized, context-specific source code. However, these agents operate primarily within localized context windows. Consequently, they lack a comprehensive understanding of global architectural boundaries, design patterns, and system-wide constraints. As a result, autonomous code modifications frequently introduce subtle regressions, bypass type contracts, violate defined package boundaries, and introduce illegal import paths, degrading code quality and architecture over time.

## Solution

Agent-Shield addresses this gap by establishing programmatic guardrails that enforce structural and runtime invariants. By combining Python decorators for runtime type verification with static AST analysis (scheduled for subsequent releases), Agent-Shield captures architectural boundary violations at the point of execution. Crucially, instead of raising generic stack traces, the library produces structured JSON reports designed specifically for ingestion by LLM-based development agents, enabling automated self-correction loops.

## Current Features

* **Runtime Type Contract Enforcement**: Automatically validates that function return values strictly adhere to declared type hints (supporting built-in types, generics, and complex union types).
* **Structured LLM Feedback Loop**: Generates standard JSON violation reports containing the exact file path, function name, expected/actual types, and clear instructions to guide AI agents in self-correction.

## Installation

Agent-Shield can be installed directly from the GitHub repository using standard package managers.

Using pip:
```bash
pip install git+https://github.com/Safik121/agent-shield.git
```

Using Poetry:
```bash
poetry add git+https://github.com/Safik121/agent-shield.git
```

## Quick Start / Usage

To enforce return type contracts on a function, apply the `shield` decorator:

```python
from agent_shield.contracts import shield

@shield
def process_payment(amount: float) -> dict:
    # Function implementation must return a dictionary as annotated
    return {
        "status": "success",
        "amount": amount
    }
```

If the decorated function violates the type contract (for instance, by returning a string instead of a dictionary), Agent-Shield catches the deviation, writes a diagnostic report to `shield_reports/violation_report.json`, and raises a `ShieldViolationError`.

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.
