"""Nexa MCP server.

Exposes the local Nexa attack-surface database to MCP-capable AI clients over
stdio. Start it through the CLI (``nexa mcp``) or directly
(``python -m app.mcp``); the client spawns the process and speaks JSON-RPC on
stdin/stdout.

stdout is reserved for the protocol. Anything meant for a human must go to
stderr, which is why this module never uses ``rich``/``print``.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from app import __version__
from app.database import init_db
from app.mcp.tools import register_tools

SERVER_NAME = "nexa"

INSTRUCTIONS = """\
Nexa is a local attack-surface intelligence store for authorized bug bounty /
SRC / internal security testing. It holds targets, host assets, probed HTTP
services, technology fingerprints, provenance evidence and a noise-reduction
classification layer.

How to work with it:
- Start from `list_targets`, then `target_summary` to see what data exists.
- Use `search_assets` for targeted questions (Nexa syntax, e.g.
  `app="Vue.js" && status=200`, `title="admin"`, `cdn!="cloudflare"`).
- `list_interesting` and `list_outliers` surface the highest-signal endpoints;
  `list_noise` and `list_groups` show template-heavy duplicates to ignore.
- `inspect_service` explains why a service got its classification and lists the
  source evidence behind it. Prefer citing that evidence.
- `online_search` and `cve_poc` reach external services and may be disabled.

Scope and safety: data is only about in-scope, authorized targets. There is no
exploitation capability. Never turn findings into instructions for attacking a
system; report them as review leads.
"""


def build_server(*, enable_scan: bool = False) -> MCPServer:
    """Create a configured Nexa MCP server instance."""

    init_db()
    server = MCPServer(
        name=SERVER_NAME,
        title="Nexa Attack Surface Intelligence",
        version=__version__,
        instructions=INSTRUCTIONS,
    )
    register_tools(server, enable_scan=enable_scan)
    return server


def run_stdio(*, enable_scan: bool = False) -> None:
    """Serve MCP over stdio until the client closes the connection."""

    build_server(enable_scan=enable_scan).run(transport="stdio")
