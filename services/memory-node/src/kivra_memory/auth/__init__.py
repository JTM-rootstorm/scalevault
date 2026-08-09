"""Public request-authentication contracts for the canonical Memory Node."""

from kivra_memory.auth.context import (
    authenticated_request_context,
    current_authenticated_request,
)
from kivra_memory.auth.contracts import (
    BEARER_TOKEN_VERSION,
    BEARER_VERIFIER_VERSION,
    CLIENT_CAPABILITY_VERSION,
    AuthenticatedRequestIdentity,
    BearerAuthenticationError,
    BearerCredential,
    BearerTokenCodec,
    BearerTokenHasher,
    ClientCapabilityProfile,
    IssuedBearerCredential,
    ReadCapability,
    RequestTransportIdentity,
    StatusIdentity,
)

__all__ = [
    "BEARER_TOKEN_VERSION",
    "BEARER_VERIFIER_VERSION",
    "CLIENT_CAPABILITY_VERSION",
    "AuthenticatedRequestIdentity",
    "BearerAuthenticationError",
    "BearerCredential",
    "BearerTokenCodec",
    "BearerTokenHasher",
    "ClientCapabilityProfile",
    "IssuedBearerCredential",
    "ReadCapability",
    "RequestTransportIdentity",
    "StatusIdentity",
    "authenticated_request_context",
    "current_authenticated_request",
]
