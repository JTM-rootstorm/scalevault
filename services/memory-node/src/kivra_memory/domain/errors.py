"""Safe domain errors that never retain or render memory payloads."""


class DomainError(Exception):
    """Base class for transport-neutral domain failures."""


class DomainValidationError(DomainError, ValueError):
    """Raised when an untrusted value is outside the domain contract."""


class DomainConstraintError(DomainValidationError):
    """Raised for a stable, machine-identifiable semantic constraint failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


class CanonicalJsonError(DomainValidationError):
    """Raised when a value cannot be represented by the canonical JSON profile."""


class InvalidIdentifierError(DomainValidationError):
    """Raised when an identifier is not a canonical RFC 9562 UUIDv7."""
