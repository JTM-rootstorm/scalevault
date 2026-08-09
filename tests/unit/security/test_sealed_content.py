from __future__ import annotations

from dataclasses import replace
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.security import (
    ContentKeyMaterial,
    ContentKeyReference,
    InvalidSealedEnvelopeError,
    SealedContentAuthenticationError,
    SealedContentContext,
    SealedContentEnvelope,
    SealedContentKeyUnavailableError,
    open_content,
    open_with_provider,
    seal_content,
)
from kivra_memory.security.sealed_content import (
    MAX_SAFE_SUMMARY_CHARACTERS,
    MAX_SEALED_PLAINTEXT_BYTES,
)

TENANT_ID = UUID("019c0000-0000-7000-8000-000000000001")
LINEAGE_ID = UUID("019c0000-0000-7000-8000-000000000002")
BRANCH_ID = UUID("019c0000-0000-7000-8000-000000000003")
MEMORY_ID = UUID("019c0000-0000-7000-8000-000000000004")
CONTENT_KEY_ID = UUID("019c0000-0000-7000-8000-000000000005")
EVENT_ID = UUID("019c0000-0000-7000-8000-000000000006")
OTHER_ID = UUID("019c0000-0000-7000-8000-000000000007")
KEY = ContentKeyMaterial(bytes(range(32)))
PLAINTEXT = b'{"statement":"synthetic private canary"}'


def context() -> SealedContentContext:
    return SealedContentContext(
        tenant_id=TENANT_ID,
        lineage_id=LINEAGE_ID,
        branch_id=BRANCH_ID,
        memory_id=MEMORY_ID,
        content_key_id=CONTENT_KEY_ID,
        revision=3,
        event_id=EVENT_ID,
        schema_version=3,
        payload_version=3,
    )


def test_aad_is_canonical_closed_and_versioned() -> None:
    aad = context().aad_bytes()

    assert aad == (
        b'{"aad_contract":"scalevault.sealed-content-aad.v1",'
        b'"algorithm":"AES-256-GCM",'
        b'"branch_id":"019c0000-0000-7000-8000-000000000003",'
        b'"content_key_id":"019c0000-0000-7000-8000-000000000005",'
        b'"event_id":"019c0000-0000-7000-8000-000000000006",'
        b'"lineage_id":"019c0000-0000-7000-8000-000000000002",'
        b'"memory_id":"019c0000-0000-7000-8000-000000000004",'
        b'"payload_version":3,"revision":3,"schema_version":3,'
        b'"tenant_id":"019c0000-0000-7000-8000-000000000001"}'
    )
    assert b"synthetic private canary" not in aad


def test_aes_256_gcm_round_trip_uses_a_fresh_96_bit_nonce() -> None:
    first = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    )
    second = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    )

    assert len(first.nonce) == 12
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert open_content(key=KEY, envelope=first, context=context()) == PLAINTEXT
    assert PLAINTEXT not in first.ciphertext


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("tenant_id", OTHER_ID),
        ("lineage_id", OTHER_ID),
        ("branch_id", OTHER_ID),
        ("memory_id", OTHER_ID),
        ("content_key_id", OTHER_ID),
        ("revision", 4),
        ("event_id", OTHER_ID),
        ("schema_version", 4),
        ("payload_version", 4),
    ],
)
def test_every_context_field_is_authenticated(field_name: str, value: object) -> None:
    envelope = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    )

    with pytest.raises(SealedContentAuthenticationError) as error:
        open_content(
            key=KEY,
            envelope=envelope,
            context=replace(context(), **cast(Any, {field_name: value})),
        )

    assert str(error.value) == "sealed content authentication failed"
    assert "canary" not in repr(error.value)


def test_ciphertext_tampering_has_one_content_free_failure() -> None:
    envelope = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    )
    tampered = replace(
        envelope,
        ciphertext=bytes([envelope.ciphertext[0] ^ 1]) + envelope.ciphertext[1:],
    )

    with pytest.raises(SealedContentAuthenticationError, match="authentication failed") as error:
        open_content(key=KEY, envelope=tampered, context=context())

    assert "canary" not in repr(error.value)


def test_json_boundary_round_trips_and_rejects_unknown_fields() -> None:
    envelope = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    )
    document = envelope.to_json_document()

    assert SealedContentEnvelope.from_json_document(document) == envelope
    document["provider_key_reference"] = "forbidden"
    with pytest.raises(InvalidSealedEnvelopeError, match="envelope is invalid"):
        SealedContentEnvelope.from_json_document(document)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("contract_version", "scalevault.sealed-content-envelope.v2"),
        ("envelope_version", True),
        ("algorithm", "AES-128-GCM"),
        ("content_key_id", str(CONTENT_KEY_ID).upper()),
        ("nonce", "AAECAwQFBgcICQoL=="),
        ("ciphertext", "not-base64"),
        ("aad_sha256", "A" * 64),
        ("safe_summary", ""),
    ],
)
def test_json_boundary_rejects_noncanonical_and_unknown_values(
    field_name: str, value: object
) -> None:
    document = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    ).to_json_document()
    document[field_name] = value

    with pytest.raises(InvalidSealedEnvelopeError, match="envelope is invalid"):
        SealedContentEnvelope.from_json_document(document)


@pytest.mark.parametrize(
    ("plaintext", "safe_summary"),
    [
        (b"", "safe"),
        (b"x" * (MAX_SEALED_PLAINTEXT_BYTES + 1), "safe"),
        (b"x", ""),
        (b"x", "x" * (MAX_SAFE_SUMMARY_CHARACTERS + 1)),
        (b"x", "\ud800"),
    ],
)
def test_plaintext_and_summary_bounds_fail_closed(plaintext: bytes, safe_summary: str) -> None:
    with pytest.raises(InvalidSealedEnvelopeError, match="envelope is invalid") as error:
        seal_content(
            key=KEY,
            plaintext=plaintext,
            context=context(),
            safe_summary=safe_summary,
        )

    assert "canary" not in repr(error.value)


def test_key_material_and_reference_representations_do_not_expose_secrets() -> None:
    reference = ContentKeyReference(
        content_key_id=CONTENT_KEY_ID,
        provider_name="synthetic-provider",
        provider_key_reference="secret-looking-reference",
    )

    assert bytes(range(32)).hex() not in repr(KEY)
    assert "secret-looking-reference" not in repr(reference)


class FailingProvider:
    name = "synthetic-provider"

    async def get_key(self, reference: ContentKeyReference) -> ContentKeyMaterial:
        del reference
        raise RuntimeError("provider leaked private diagnostic")


async def test_provider_diagnostics_are_replaced_by_safe_error() -> None:
    reference = ContentKeyReference(
        content_key_id=CONTENT_KEY_ID,
        provider_name="synthetic-provider",
        provider_key_reference="opaque-ref",
    )
    envelope = seal_content(
        key=KEY,
        plaintext=PLAINTEXT,
        context=context(),
        safe_summary="Reviewed safe summary.",
    )

    with pytest.raises(SealedContentKeyUnavailableError) as error:
        await open_with_provider(
            provider=FailingProvider(),  # type: ignore[arg-type]
            reference=reference,
            envelope=envelope,
            context=context(),
        )

    assert str(error.value) == "sealed content key is unavailable"
    assert "private diagnostic" not in repr(error.value)
