"""Async-task-local authenticated request context for transport adapters."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from kivra_memory.auth.contracts import AuthenticatedRequestIdentity

_CURRENT_AUTHENTICATED_REQUEST: ContextVar[AuthenticatedRequestIdentity | None] = ContextVar(
    "scalevault_authenticated_request",
    default=None,
)


@contextmanager
def authenticated_request_context(
    identity: AuthenticatedRequestIdentity,
) -> Iterator[AuthenticatedRequestIdentity]:
    """Install one verified identity for the exact request and reliably remove it."""

    if not isinstance(identity, AuthenticatedRequestIdentity):
        raise TypeError("authenticated request identity is invalid")
    token = _CURRENT_AUTHENTICATED_REQUEST.set(identity)
    try:
        yield identity
    finally:
        _CURRENT_AUTHENTICATED_REQUEST.reset(token)


def current_authenticated_request() -> AuthenticatedRequestIdentity | None:
    """Return the current request identity without manufacturing a fallback."""

    return _CURRENT_AUTHENTICATED_REQUEST.get()


__all__ = ["authenticated_request_context", "current_authenticated_request"]
