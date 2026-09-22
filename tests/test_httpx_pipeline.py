"""Tests for httpx streaming execution and probe-asset selection."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from sqlmodel import Session, SQLModel, create_engine

import app.models  # noqa: F401  (register SQLModel tables)
from app.collectors.base import CollectorError, run_command_streaming
from app.collectors.httpx_runner import HTTPProbeResult, HTTPXRunner, ProbeOutcome
from app.models.asset import Asset
from app.models.service import Service
from app.models.target import Target
from app.pipelines.recon import _probe_assets_in_batches, _select_probe_assets
from app.repositories import ServiceRepository


def _naive(year: int, month: int, day: int) -> datetime:
    """SQLite stores and returns naive UTC datetimes; mirror that in tests."""

    return datetime(year, month, day)  # noqa: DTZ001


class StreamingCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_streams_lines_and_emits_progress(self) -> None:
        lines: list[str] = []
        ticks: list[float] = []
        script = "import time\nfor i in range(3):\n    print(i, flush=True)\n    time.sleep(0.05)\n"

        result = await run_command_streaming(
            [sys.executable, "-c", script],
            timeout=10,
            on_stdout_line=lines.append,
            on_progress=lambda progress: ticks.append(progress.elapsed),
            progress_interval=0.05,
        )

        self.assertFalse(result.timed_out)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(lines, ["0", "1", "2"])
        self.assertGreaterEqual(len(ticks), 1)

    async def test_timeout_keeps_partial_output(self) -> None:
        script = "import time\nprint('first', flush=True)\ntime.sleep(30)\n"

        result = await run_command_streaming([sys.executable, "-c", script], timeout=1)

        self.assertTrue(result.timed_out)
        self.assertIn("first", result.stdout)
        self.assertNotEqual(result.returncode, 0)

    async def test_missing_binary_raises_collector_error(self) -> None:
        with self.assertRaises(CollectorError):
            await run_command_streaming(["/nonexistent/nexa-tool"], timeout=5)


class HttpxCommandTests(unittest.TestCase):
    def test_build_command_includes_tuning_flags(self) -> None:
        runner = HTTPXRunner(
            binary="/tmp/httpx",
            timeout=600,
            request_timeout=7,
            retries=1,
            rate_limit=250,
            threads=150,
        )
        command = runner.build_command(Path("/tmp/hosts.txt"))

        self.assertIn("-timeout", command)
        self.assertEqual(command[command.index("-timeout") + 1], "7")
        self.assertEqual(command[command.index("-retries") + 1], "1")
        self.assertEqual(command[command.index("-rate-limit") + 1], "250")
        self.assertEqual(command[command.index("-threads") + 1], "150")
        self.assertIn("-disable-update-check", command)
        self.assertNotIn("-include-response-header", command)

        enrich = runner.build_command(Path("/tmp/hosts.txt"), enrich=True)
        self.assertIn("-include-response-header", enrich)


class ProbeSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite:///{Path(self._tmp.name) / 'probe.db'}",
            connect_args={"check_same_thread": False},
        )
        SQLModel.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        self.target = Target(name="example.com", root_domain="example.com")
        self.session.add(self.target)
        self.session.commit()
        self.session.refresh(self.target)

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()
        self._tmp.cleanup()

    def _asset(self, host: str, first_seen: datetime, is_alive: bool = False) -> Asset:
        asset = Asset(
            target_id=self.target.id,
            host=host,
            source="subfinder",
            is_alive=is_alive,
            first_seen=first_seen,
            last_seen=first_seen,
        )
        self.session.add(asset)
        self.session.commit()
        self.session.refresh(asset)
        return asset

    def _service(self, asset: Asset, checked_at: datetime) -> None:
        self.session.add(
            Service(
                asset_id=asset.id,
                url=f"https://{asset.host}",
                scheme="https",
                last_checked_at=checked_at,
            )
        )
        self.session.commit()

    def test_skips_known_dead_and_keeps_alive_and_new(self) -> None:
        old = _naive(2020, 1, 1)
        new = _naive(2030, 1, 1)
        alive = self._asset("alive.example.com", old, is_alive=True)
        self._asset("dead.example.com", old)
        self._asset("fresh.example.com", new)
        self._service(alive, _naive(2025, 1, 1))

        selected, skipped = _select_probe_assets(self.session, self.target.id)

        self.assertEqual({asset.host for asset in selected}, {"alive.example.com", "fresh.example.com"})
        self.assertEqual(skipped, 1)

    def test_rescan_dead_probes_everything(self) -> None:
        old = _naive(2020, 1, 1)
        alive = self._asset("alive.example.com", old, is_alive=True)
        self._asset("dead.example.com", old)
        self._service(alive, _naive(2025, 1, 1))

        selected, skipped = _select_probe_assets(self.session, self.target.id, rescan_dead=True)

        self.assertEqual(len(selected), 2)
        self.assertEqual(skipped, 0)

    def test_first_scan_probes_everything(self) -> None:
        old = _naive(2020, 1, 1)
        self._asset("alive.example.com", old, is_alive=True)
        self._asset("dead.example.com", old)

        selected, skipped = _select_probe_assets(self.session, self.target.id)

        self.assertEqual(len(selected), 2)
        self.assertEqual(skipped, 0)


class _StubRunner:
    """Returns canned outcomes so batching can be tested without httpx."""

    def __init__(self, outcomes: list[ProbeOutcome]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def probe_file(self, hosts_file, enrich=False, label="httpx", on_progress=None) -> ProbeOutcome:
        outcome = self._outcomes[self.calls]
        self.calls += 1
        return outcome


class BatchPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite:///{Path(self._tmp.name) / 'batch.db'}",
            connect_args={"check_same_thread": False},
        )
        SQLModel.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        self.target = Target(name="example.com", root_domain="example.com")
        self.session.add(self.target)
        self.session.commit()
        self.session.refresh(self.target)
        self.assets = [
            Asset(target_id=self.target.id, host=f"h{i}.example.com", source="subfinder")
            for i in range(4)
        ]
        for asset in self.assets:
            self.session.add(asset)
        self.session.commit()
        for asset in self.assets:
            self.session.refresh(asset)

    async def asyncTearDown(self) -> None:
        self.session.close()
        self.engine.dispose()
        self._tmp.cleanup()

    async def test_batch_results_persist_even_when_a_later_batch_times_out(self) -> None:
        messages: list[str] = []
        outcomes = [
            ProbeOutcome(
                results=[HTTPProbeResult(url=f"https://{self.assets[0].host}")],
                duration=1.0,
            ),
            ProbeOutcome(
                results=[HTTPProbeResult(url=f"https://{self.assets[2].host}")],
                duration=900.0,
                timed_out=True,
                error="timed out after 900s",
            ),
        ]
        runner = _StubRunner(outcomes)

        with patch(
            "app.pipelines.recon._write_hosts_file",
            lambda *args, **kwargs: Path(self._tmp.name) / "hosts.txt",
        ):
            stats = await _probe_assets_in_batches(
                session=self.session,
                target_id=self.target.id,
                runner=runner,
                target_name="example.com",
                assets=self.assets,
                batch_size=2,
                progress_callback=messages.append,
            )

        # The first batch must be committed even though the second timed out.
        services = ServiceRepository(self.session).list_by_target(self.target.id)
        self.assertEqual(
            {service.url for service in services},
            {f"https://{self.assets[0].host}", f"https://{self.assets[2].host}"},
        )
        self.assertEqual(stats.services_seen, 2)
        self.assertEqual(stats.hosts_probed, 4)
        self.assertEqual(len(stats.errors), 1)
        self.assertIn("timed out", stats.errors[0])
        self.assertTrue(any("kept 1 responses" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
