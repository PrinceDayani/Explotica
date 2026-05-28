"""Production safety kit — scope, shutdown, checkpoint, retry, logging.

Cross-cutting infrastructure that wraps active checks and CLI lifecycle.
Depends on: core (constants only).
"""

from .safety import (
    Scope, ScopeViolation,
    SafeMode, RateLimiter,
    set_active_scope, get_active_scope, in_scope, require_in_scope,
    set_safe_mode, get_safe_mode, safe_to_run,
    show_authorization_banner, classify_args_risk,
)
from .shutdown import (
    ShutdownToken, get_token, reset, install_signal_handlers,
)
from .checkpoint import Checkpoint
from .retry import (
    retry, retry_call, exponential_backoff,
    CircuitBreaker, BreakerOpen, get_breaker,
)
from .logging_config import configure as configure_logging

__all__ = [
    # safety
    "Scope", "ScopeViolation", "SafeMode", "RateLimiter",
    "set_active_scope", "get_active_scope", "in_scope", "require_in_scope",
    "set_safe_mode", "get_safe_mode", "safe_to_run",
    "show_authorization_banner", "classify_args_risk",
    # shutdown
    "ShutdownToken", "get_token", "reset", "install_signal_handlers",
    # checkpoint
    "Checkpoint",
    # retry
    "retry", "retry_call", "exponential_backoff",
    "CircuitBreaker", "BreakerOpen", "get_breaker",
    # logging
    "configure_logging",
]
