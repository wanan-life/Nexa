from pathlib import Path

from app.collectors.base import CollectedAsset, Collector, run_command
from app.utils.normalize import normalize_host


def parse_subfinder_file(path: Path) -> list[CollectedAsset]:
    assets: list[CollectedAsset] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        assets.append(CollectedAsset(host=normalize_host(value), source="subfinder"))
    return assets


class SubfinderCollector(Collector):
    name = "subfinder"

    def __init__(
        self,
        binary: str = "subfinder",
        config: Path | None = None,
        provider_config: Path | None = None,
        timeout: int = 900,
    ) -> None:
        self.binary = binary
        self.config = config
        self.provider_config = provider_config
        self.timeout = timeout

    async def collect(self, target: str) -> list[CollectedAsset]:
        command = [self.binary, "-d", target, "-silent"]
        if self.config:
            command.extend(["-config", str(self.config)])
        if self.provider_config:
            command.extend(["-pc", str(self.provider_config)])
        result = await run_command(command, timeout=self.timeout)
        hosts = []
        for line in result.stdout.splitlines():
            value = line.strip()
            if value:
                hosts.append(CollectedAsset(host=normalize_host(value), source=self.name))
        return hosts
