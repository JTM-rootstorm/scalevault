"""Minimal MCP capability probe with no access to memory storage."""

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations


def create_echo_mcp() -> FastMCP[None]:
    """Create the stateless Streamable HTTP server used by the capability probe."""

    server: FastMCP[None] = FastMCP(
        name="ScaleVault MCP Echo Probe",
        instructions="Echoes text for transport verification. It does not access memory data.",
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
    )

    @server.tool(
        name="echo",
        title="Echo text",
        description="Return the supplied text unchanged without reading or writing memory data.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
        structured_output=False,
    )
    async def echo(message: str) -> str:
        """Return the supplied transport probe text unchanged."""

        return message

    return server
