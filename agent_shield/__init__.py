from .contracts import shield, ShieldViolationError, TimeoutViolationError, MemoryViolationError, NetworkViolationError, PromptAssertionError, FilesystemViolationError
from .freezer import freeze
from .injector import prompt_inject
from .signature_lock import lock_signature
from .sandbox import mock_only
from .timeout import timeout
from .memory_limit import limit_memory
from .network_sandbox import restrict_network
from .semantic import prompt_assert
from .config import init_config
from .fs_sandbox import restrict_fs

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
    "freeze",
    "prompt_inject",
    "lock_signature",
    "mock_only",
    "timeout",
    "limit_memory",
    "restrict_network",
    "prompt_assert",
    "init_config",
    "restrict_fs",
]
