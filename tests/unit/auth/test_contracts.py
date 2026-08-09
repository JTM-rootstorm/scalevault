from __future__ import annotations

import base64
import hashlib
import hmac
from uuid import UUID

import pytest
from kivra_memory.auth import (
    BearerAuthenticationError,
    BearerTokenCodec,
    BearerTokenHasher,
)
from kivra_memory.domain.identifiers import new_uuid7

PEPPER = bytes(range(32))
TENANT_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=1)
CREDENTIAL_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=2)


def test_issued_token_and_verifier_match_frozen_wire_contract() -> None:
    hasher = BearerTokenHasher(PEPPER)
    issued = BearerTokenCodec.issue(
        TENANT_ID,
        CREDENTIAL_ID,
        hasher,
        random_bytes=lambda size: b"\x5a" * size,
    )

    secret = base64.urlsafe_b64encode(b"\x5a" * 32).rstrip(b"=").decode("ascii")
    expected_token = f"svb1.{TENANT_ID}.{CREDENTIAL_ID}.{secret}"
    digest = hmac.new(
        PEPPER,
        b"scalevault-client-bearer-token-v1\x00" + expected_token.encode("ascii"),
        hashlib.sha256,
    ).digest()
    expected_digest = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    assert issued.token == expected_token
    assert issued.secret_hash == f"hmac-sha256-v1:{expected_digest}"
    parsed = BearerTokenCodec.parse_authorization(f"Bearer {issued.token}")
    assert parsed.tenant_id == TENANT_ID
    assert parsed.credential_id == CREDENTIAL_ID
    assert hasher.verify(parsed, issued.secret_hash)
    assert "svb1" not in repr(issued)
    assert secret not in repr(issued)
    assert secret not in repr(parsed)
    assert PEPPER.hex() not in repr(hasher)


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Bearer  token",
        "Bearer token ",
        "Basic token",
        "Bearer svb1.not-a-tenant.not-a-credential.secret",
        f"Bearer svb1.{TENANT_ID}.{CREDENTIAL_ID}.{'A' * 42}",
        f"Bearer svb1.{TENANT_ID}.{UUID(int=0)}.{'A' * 43}",
        f"Bearer svb1.{str(TENANT_ID).upper()}.{CREDENTIAL_ID}.{'A' * 43}",
        f"Bearer svb1.{TENANT_ID}.{CREDENTIAL_ID}.{'A' * 43},extra",
        "Bearer " + "A" * 257,
    ],
)
def test_every_malformed_header_has_one_safe_failure(header: str | None) -> None:
    with pytest.raises(BearerAuthenticationError) as caught:
        BearerTokenCodec.parse_authorization(header)

    assert str(caught.value) == "authentication failed"
    assert not header or header not in str(caught.value)


def test_scheme_is_case_insensitive_but_token_is_canonical() -> None:
    issued = BearerTokenCodec.issue(
        TENANT_ID,
        CREDENTIAL_ID,
        BearerTokenHasher(PEPPER),
        random_bytes=lambda size: b"\x33" * size,
    )

    assert BearerTokenCodec.parse_authorization(f"bearer {issued.token}").tenant_id == TENANT_ID


def test_verification_rejects_wrong_secret_key_and_verifier_shape() -> None:
    issued = BearerTokenCodec.issue(
        TENANT_ID,
        CREDENTIAL_ID,
        BearerTokenHasher(PEPPER),
        random_bytes=lambda size: b"\x22" * size,
    )
    parsed = BearerTokenCodec.parse_authorization(f"Bearer {issued.token}")

    assert not BearerTokenHasher(b"x" * 32).verify(parsed, issued.secret_hash)
    assert not BearerTokenHasher(PEPPER).verify(parsed, "hmac-sha256-v1$" + "A" * 43)
    assert not BearerTokenHasher(PEPPER).verify(parsed, "not-a-verifier")


@pytest.mark.parametrize("pepper", [b"", b"x" * 31])
def test_hasher_rejects_short_pepper_without_echoing_it(pepper: bytes) -> None:
    with pytest.raises(ValueError, match="at least 32 bytes") as caught:
        BearerTokenHasher(pepper)

    assert not pepper or pepper.hex() not in str(caught.value)
