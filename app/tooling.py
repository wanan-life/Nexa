import sys
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings


@dataclass(frozen=True)
class ToolStatus:
    name: str
    path: Path
    installed: bool
    kind: str
    note: str = ""


class ToolResolver:
    """Resolve bundled reconnaissance tools from Nexa/tools."""

    def __init__(self, tools_dir: Path | None = None) -> None:
        self.tools_dir = tools_dir or get_settings().tools_dir

    @property
    def subfinder_binary(self) -> Path:
        return self.tools_dir / "subfinder" / "subfinder"

    @property
    def subfinder_config(self) -> Path:
        return self.tools_dir / "subfinder" / "config.yaml"

    @property
    def subfinder_provider_config(self) -> Path:
        return self.tools_dir / "subfinder" / "provider-config.yaml"

    @property
    def httpx_binary(self) -> Path:
        return self.tools_dir / "httpx" / "httpx"

    @property
    def oneforall_entrypoint(self) -> Path:
        return self.tools_dir / "OneForAll" / "oneforall.py"

    @property
    def oneforall_workdir(self) -> Path:
        return self.tools_dir / "OneForAll"

    @property
    def oneforall_python(self) -> Path:
        venv_python = self.oneforall_workdir / ".venv" / "bin" / "python"
        if venv_python.exists():
            return venv_python
        return Path(sys.executable)

    def statuses(self) -> list[ToolStatus]:
        return [
            ToolStatus("subfinder", self.subfinder_binary, self.subfinder_binary.exists(), "binary"),
            ToolStatus("httpx", self.httpx_binary, self.httpx_binary.exists(), "binary"),
            ToolStatus(
                "OneForAll",
                self.oneforall_entrypoint,
                self.oneforall_entrypoint.exists(),
                "python",
                "dependencies must be installed in tools/OneForAll/.venv or current Python",
            ),
        ]
