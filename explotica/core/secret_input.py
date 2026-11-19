"""Resolve secret-bearing CLI values without exposing them in argv.

Passing credentials directly as command-line arguments leaks them into the
process table (``ps``) and the shell history. These helpers let a credential
flag instead reference an environment variable or a file:

    --ssh-creds env:SSH_CREDS      # value read from $SSH_CREDS
    --ssh-creds file:/run/creds    # value read from the file (trimmed)
    --ssh-creds root:hunter2       # literal (still accepted, back-compat)

A literal value is returned unchanged, so existing invocations keep working.
"""

from __future__ import annotations

import os


class SecretResolutionError(ValueError):
    """Raised when an ``env:``/``file:`` reference cannot be resolved."""


def resolve_secret(value: str | None) -> str | None:
    """Expand an ``env:NAME`` or ``file:PATH`` reference to its secret value.

    Returns ``None`` for ``None`` input. A plain string with no recognised
    prefix is returned unchanged. ``file:`` contents are stripped of a single
    trailing newline (common when a secret is echoed into a file).

    Raises SecretResolutionError if the referenced variable is unset/empty or
    the file is missing/unreadable, so a misconfigured reference fails loudly
    instead of silently scanning with an empty credential.
    """
    if value is None:
        return None
    if value.startswith("env:"):
        name = value[len("env:"):]
        resolved = os.environ.get(name)
        if not resolved:
            raise SecretResolutionError(
                f"environment variable {name!r} is unset or empty"
            )
        return resolved
    if value.startswith("file:"):
        path = value[len("file:"):]
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read().rstrip("\n")
        except OSError as exc:
            raise SecretResolutionError(
                f"could not read secret file {path!r}: {exc}"
            ) from exc
        if not content:
            raise SecretResolutionError(
                f"secret file {path!r} is empty"
            )
        return content
    return value
