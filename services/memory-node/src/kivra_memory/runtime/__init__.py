"""Production runtime composition for the canonical Memory Node."""

from kivra_memory.runtime.authentication import (
    DirectBearerAuthenticationMiddleware,
    RequestBearerAuthenticator,
    current_command_principal,
    current_query_principal,
)
from kivra_memory.runtime.composition import MemoryNodeRuntime
from kivra_memory.runtime.nomination import DirectNominationResolver

__all__ = [
    "DirectBearerAuthenticationMiddleware",
    "DirectNominationResolver",
    "MemoryNodeRuntime",
    "RequestBearerAuthenticator",
    "current_command_principal",
    "current_query_principal",
]
