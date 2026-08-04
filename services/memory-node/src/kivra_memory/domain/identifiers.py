"""RFC 9562 UUIDv7 generation and validation."""

import secrets
import time
from uuid import RFC_4122, UUID

from kivra_memory.domain.errors import InvalidIdentifierError

UUID7_TIMESTAMP_BITS = 48
UUID7_RANDOM_BITS = 74
MAX_UUID7_TIMESTAMP_MS = (1 << UUID7_TIMESTAMP_BITS) - 1
MAX_UUID7_RANDOM = (1 << UUID7_RANDOM_BITS) - 1


def new_uuid7(*, timestamp_ms: int | None = None, random_bits: int | None = None) -> UUID:
    """Create a UUIDv7 without treating its timestamp as semantic ordering."""

    resolved_timestamp = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    resolved_random = secrets.randbits(UUID7_RANDOM_BITS) if random_bits is None else random_bits
    if (
        isinstance(resolved_timestamp, bool)
        or not 0 <= resolved_timestamp <= MAX_UUID7_TIMESTAMP_MS
    ):
        raise InvalidIdentifierError("UUIDv7 timestamp is outside the 48-bit range")
    if isinstance(resolved_random, bool) or not 0 <= resolved_random <= MAX_UUID7_RANDOM:
        raise InvalidIdentifierError("UUIDv7 random value is outside the 74-bit range")

    random_a = resolved_random >> 62
    random_b = resolved_random & ((1 << 62) - 1)
    value = (resolved_timestamp << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    return UUID(int=value)


def is_uuid7(value: object) -> bool:
    """Return whether a value is an RFC-variant UUID version 7."""

    return isinstance(value, UUID) and value.version == 7 and value.variant == RFC_4122


def require_uuid7(value: UUID, *, field_name: str = "identifier") -> UUID:
    """Return a validated UUIDv7 or raise a payload-safe validation error."""

    if not is_uuid7(value):
        raise InvalidIdentifierError(f"{field_name} must be an RFC 9562 UUIDv7")
    return value
