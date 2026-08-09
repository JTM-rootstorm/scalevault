"""Production runtime composition for the canonical Memory Node."""

from kivra_memory.runtime.authentication import (
    DirectBearerAuthenticationMiddleware,
    RequestBearerAuthenticator,
    current_command_principal,
    current_query_principal,
)
from kivra_memory.runtime.chatgpt import (
    ChatGPTReadRuntime,
    SecureTunnelBearerAuthenticator,
    SecureTunnelReadAuthenticationMiddleware,
    current_secure_tunnel_query,
    current_secure_tunnel_query_principal,
)
from kivra_memory.runtime.composition import MemoryNodeRuntime
from kivra_memory.runtime.nomination import DirectNominationResolver

__all__ = [
    "ChatGPTReadRuntime",
    "DirectBearerAuthenticationMiddleware",
    "DirectNominationResolver",
    "MemoryNodeRuntime",
    "RequestBearerAuthenticator",
    "SecureTunnelBearerAuthenticator",
    "SecureTunnelReadAuthenticationMiddleware",
    "current_command_principal",
    "current_query_principal",
    "current_secure_tunnel_query",
    "current_secure_tunnel_query_principal",
]
