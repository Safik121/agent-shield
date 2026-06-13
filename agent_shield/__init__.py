from .contracts import shield, ShieldViolationError, TimeoutViolationError, MemoryViolationError, NetworkViolationError, PromptAssertionError, FilesystemViolationError, SideEffectViolationError, ComplexityViolationError, SubprocessViolationError, SecretsLeakViolationError, CallLimitViolationError, EnvironmentViolationError, restrict_env, DatabaseViolationError, PromptInjectionViolationError
from .freezer import freeze
from .injector import prompt_inject
from .signature_lock import lock_signature
from .sandbox import mock_only
from .timeout import timeout
from .memory_limit import limit_memory
from .network_sandbox import restrict_network, limit_calls
from .semantic import prompt_assert
from .config import init_config
from .fs_sandbox import restrict_fs
from .side_effects import no_side_effects
from .subprocess_sandbox import restrict_subprocess
from .secrets_sandbox import no_secrets_leak
from .virtual_fs import virtual_fs
from .prompt_guard import guard_prompt
from .db_sandbox import restrict_db

# Auto-initialize configuration-based auto-decoration if shield.yaml is present in project root
init_config()

__all__ = [
    "shield",
    "ShieldViolationError",
    "TimeoutViolationError",
    "MemoryViolationError",
    "NetworkViolationError",
    "PromptAssertionError",
    "FilesystemViolationError",
    "SideEffectViolationError",
    "ComplexityViolationError",
    "SubprocessViolationError",
    "SecretsLeakViolationError",
    "CallLimitViolationError",
    "EnvironmentViolationError",
    "DatabaseViolationError",
    "PromptInjectionViolationError",
    "freeze",
    "prompt_inject",
    "lock_signature",
    "mock_only",
    "timeout",
    "limit_memory",
    "restrict_network",
    "limit_calls",
    "prompt_assert",
    "init_config",
    "restrict_fs",
    "no_side_effects",
    "restrict_subprocess",
    "no_secrets_leak",
    "restrict_env",
    "virtual_fs",
    "guard_prompt",
    "restrict_db",
]
