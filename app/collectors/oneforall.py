import csv
from pathlib import Path

from app.collectors.base import CollectedAsset, Collector, CollectorError, run_command
from app.utils.normalize import normalize_host


def parse_oneforall_file(path: Path) -> list[CollectedAsset]:
    assets: list[CollectedAsset] = []
    text = path.read_text(encoding="utf-8-sig")
    sample = text.lstrip()
    if not sample:
        return assets

    if "subdomain" in sample.splitlines()[0].lower():
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            host = _first_value(row, ["subdomain", "host", "domain", "url"])
            if not host:
                continue
            assets.append(
                CollectedAsset(
                    host=normalize_host(host),
                    source="oneforall",
                    ip=_first_value(row, ["ip", "ips"]),
                    cname=_first_value(row, ["cname"]),
                )
            )
        return assets

    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        host = value.split(",")[0].strip()
        assets.append(CollectedAsset(host=normalize_host(host), source="oneforall"))
    return assets


def _first_value(row: dict[str, str | None], keys: list[str]) -> str | None:
    lowered = {key.lower(): value for key, value in row.items() if key}
    for key in keys:
        value = lowered.get(key)
        if value:
            return value.strip()
    return None


class OneForAllCollector(Collector):
    name = "oneforall"

    def __init__(self, python_binary: Path, entrypoint: Path, workdir: Path, timeout: int = 1800) -> None:
        self.python_binary = python_binary
        self.entrypoint = entrypoint
        self.workdir = workdir
        self.timeout = timeout

    async def collect(self, target: str) -> list[CollectedAsset]:
        if not self.entrypoint.exists():
            raise CollectorError(f"OneForAll entrypoint not found: {self.entrypoint}")
        command = [str(self.python_binary), str(self.entrypoint), "--target", target, "--fmt", "csv", "run"]
        await run_command(command, cwd=self.workdir, timeout=self.timeout)
        return self._read_results(target)

    def _read_results(self, target: str) -> list[CollectedAsset]:
        results_dir = self.workdir / "results"
        if not results_dir.exists():
            raise CollectorError(f"OneForAll results directory not found: {results_dir}")

        candidates = [
            results_dir / f"{target}.csv",
            results_dir / f"{target.replace('.', '_')}.csv",
        ]
        candidates.extend(sorted(results_dir.glob("all_subdomain_result_*.csv"), reverse=True))
        candidates.extend(sorted(results_dir.glob("*.csv"), reverse=True))

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                parsed = parse_oneforall_file(candidate)
                if parsed:
                    return parsed
        raise CollectorError(f"OneForAll completed but no subdomain CSV rows were found in {results_dir}")
