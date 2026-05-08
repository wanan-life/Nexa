import asyncio
import shlex
from abc import ABC, abstractmethod
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


async def run_command(command: list[str], cwd: Path | None = None, timeout: int = 900) -> CommandResult:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise CollectorError(f"tool not found: {command[0]}") from exc

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise CollectorError(f"tool timed out after {timeout}s: {' '.join(command)}") from exc

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    result = CommandResult(command=command, stdout=stdout, stderr=stderr, returncode=process.returncode)
    if result.returncode != 0:
        detail = stderr.strip() or stdout.strip()
        raise CollectorError(f"tool failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def render_command_template(template: str, **values: str) -> list[str]:
    rendered = template.format(**values)
    return shlex.split(rendered)
