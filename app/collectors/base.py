import asyncio
import shlex
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CollectedAsset:
    host: str
    source: str
    ip: str | None = None
    cname: str | None = None


class Collector(ABC):
    """Base class for every external tool adapter."""

    name: str

    @abstractmethod
    async def collect(self, target: str) -> list[CollectedAsset]:
        """Collect assets for a target without writing to storage."""


class CollectorError(RuntimeError):
    """Raised when a collector cannot complete successfully."""


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    duration: float = 0.0
    timed_out: bool = False


@dataclass(frozen=True)
class CommandProgress:
    """A periodic liveness snapshot for a running command."""

    elapsed: float
    stdout_lines: int
    stderr_lines: int


LineCallback = Callable[[str], None]
ProgressCallback = Callable[[CommandProgress], None]


async def run_command(command: list[str], cwd: Path | None = None, timeout: int = 900) -> CommandResult:
    """Run a command to completion, raising ``CollectorError`` on failure or timeout."""

    result = await run_command_streaming(command, cwd=cwd, timeout=timeout)
    if result.timed_out:
        raise CollectorError(f"tool timed out after {timeout}s: {' '.join(command)}")
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CollectorError(f"tool failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


async def run_command_streaming(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 900,
    on_stdout_line: LineCallback | None = None,
    on_progress: ProgressCallback | None = None,
    progress_interval: float = 5.0,
) -> CommandResult:
    """Run a command while streaming stdout lines and periodic progress.

    Unlike :func:`run_command`, this never raises on a non-zero exit or a
    timeout: a timed-out process is killed and the output collected so far is
    returned with ``timed_out=True``. That lets long-running tools such as
    httpx keep the results they already produced instead of losing a whole
    batch of work.
    """

    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise CollectorError(f"tool not found: {command[0]}") from exc

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    counters = {"stdout": 0, "stderr": 0}

    async def pump(stream: asyncio.StreamReader, sink: list[str], key: str) -> None:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            sink.append(text)
            counters[key] += 1
            if key == "stdout" and on_stdout_line and text.strip():
                on_stdout_line(text)

    readers = [
        asyncio.create_task(pump(process.stdout, stdout_lines, "stdout")),
        asyncio.create_task(pump(process.stderr, stderr_lines, "stderr")),
    ]

    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(progress_interval)
            if on_progress:
                on_progress(
                    CommandProgress(
                        elapsed=time.monotonic() - started,
                        stdout_lines=counters["stdout"],
                        stderr_lines=counters["stderr"],
                    )
                )

    heartbeat_task = asyncio.create_task(heartbeat()) if on_progress else None
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        _terminate(process)
        await process.wait()
    finally:
        if heartbeat_task:
            heartbeat_task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        if heartbeat_task:
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    returncode = process.returncode if process.returncode is not None else -1
    return CommandResult(
        command=command,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        returncode=returncode,
        duration=time.monotonic() - started,
        timed_out=timed_out,
    )


def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.kill()
    except ProcessLookupError:
        pass


def render_command_template(template: str, **values: str) -> list[str]:
    rendered = template.format(**values)
    return shlex.split(rendered)
