"""Tests for the Nexa MCP server (tools, protocol wiring and stdio handshake)."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_TMP_DIR = tempfile.mkdtemp(prefix="nexa-mcp-test-")
_DB_URL = f"sqlite:///{Path(_TMP_DIR) / 'test.db'}"

# Point the application at a throwaway database before anything reads settings.
os.environ["NEXA_DATABASE_URL"] = _DB_URL
os.environ["NEXA_DATA_DIR"] = _TMP_DIR

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver.exceptions import ToolError

from app import database
from app.config import get_settings
from app.mcp.server import build_server


def _reset_database() -> None:
    """Rebind the global engine to the throwaway database and seed one target."""

    get_settings.cache_clear()
    database.engine = database.get_engine()
    database.init_db()

    from app.noise import classify_target_assets
    from app.repositories import AssetRepository, ServiceRepository, TargetRepository
    from app.schemas.asset import AssetCreate
    from app.schemas.service import ServiceCreate
    from app.schemas.target import TargetCreate

    with database.create_session() as session:
        target = TargetRepository(session).create(
            TargetCreate(name="example.com", program_name="Example Program")
        )
        asset = AssetRepository(session).upsert(
            AssetCreate(
                target_id=target.id,
                host="api.example.com",
                source="subfinder",
                ip="10.0.0.1",
                is_alive=True,
            )
        )
        ServiceRepository(session).upsert(
            ServiceCreate(
                asset_id=asset.id,
                url="https://api.example.com",
                status_code=200,
                title="Admin Console",
                server="nginx",
                technologies=["Vue.js"],
                response_headers={"server": "nginx", "x-powered-by": "Express"},
            )
        )
        classify_target_assets(session, target.id)


def setUpModule() -> None:
    _reset_database()


def tearDownModule() -> None:
    database.engine.dispose()


class McpToolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = build_server()

    async def test_lists_read_only_tools_by_default(self) -> None:
        tools = await self.server.list_tools()
        names = {tool.name for tool in tools}
        self.assertIn("list_targets", names)
        self.assertIn("search_assets", names)
        self.assertIn("inspect_service", names)
        self.assertNotIn("scan_target", names)

    async def test_scan_tool_is_opt_in(self) -> None:
        server = build_server(enable_scan=True)
        names = {tool.name for tool in await server.list_tools()}
        self.assertIn("scan_target", names)

    async def test_list_targets_returns_seeded_target(self) -> None:
        result = await self.server.call_tool("list_targets", {})
        self.assertFalse(result.is_error)
        self.assertIn("example.com", result.content[0].text)

    async def test_search_assets_matches_technology(self) -> None:
        result = await self.server.call_tool(
            "search_assets", {"target_ref": "example.com", "query": 'app="Vue.js"'}
        )
        self.assertFalse(result.is_error)
        self.assertIn("api.example.com", result.content[0].text)

    async def test_search_assets_rejects_unknown_field(self) -> None:
        with self.assertRaises(ToolError):
            await self.server.call_tool(
                "search_assets", {"target_ref": "example.com", "query": "nope=1"}
            )

    async def test_unknown_target_raises_tool_error(self) -> None:
        with self.assertRaises(ToolError):
            await self.server.call_tool("get_target", {"target_ref": "missing.example"})

    async def test_limit_is_clamped(self) -> None:
        result = await self.server.call_tool("list_services", {"target_ref": "example.com", "limit": 100000})
        self.assertFalse(result.is_error)
        self.assertIn('"limit": 200', result.content[0].text)

    async def test_classification_views_do_not_recurse(self) -> None:
        # Regression guard: the tool named list_outliers must call the noise
        # helper, not itself.
        for tool_name in ("list_interesting", "list_noise", "list_outliers", "list_groups"):
            result = await self.server.call_tool(tool_name, {"target_ref": "example.com"})
            self.assertFalse(result.is_error, tool_name)


class McpStdioTests(unittest.TestCase):
    """End-to-end check over the real stdio transport used by AI clients."""

    def test_handshake_list_and_tool_error(self) -> None:
        asyncio.run(self._exercise_stdio())

    async def _exercise_stdio(self) -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "app.mcp"],
            env={**os.environ, "NEXA_DATABASE_URL": _DB_URL, "NEXA_DATA_DIR": _TMP_DIR},
            cwd=str(PROJECT_ROOT),
        )
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            self.assertEqual(init.server_info.name, "nexa")

            tools = await session.list_tools()
            self.assertIn("list_targets", {tool.name for tool in tools.tools})

            ok = await session.call_tool("list_targets", {})
            self.assertFalse(ok.is_error)

            # Anticipated failures must reach the model as isError results.
            bad = await session.call_tool("get_target", {"target_ref": "missing.example"})
            self.assertTrue(bad.is_error)
            self.assertIn("target not found", bad.content[0].text)


if __name__ == "__main__":
    unittest.main()
