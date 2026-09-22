from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.0"

# Keep PyInstaller's build cache inside the project instead of the user profile
# so builds stay reproducible and do not depend on $HOME write access.
os.environ.setdefault("PYINSTALLER_CONFIG_DIR", str(ROOT / ".pyinstaller"))


def main() -> None:
    _require_frontend_bundle()
    output_name = release_asset_name()
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "nexa",
        "--add-data",
        f"{ROOT / 'web' / 'dist'}:web/dist",
        "--add-data",
        f"{ROOT / 'config' / 'nexa.example.toml'}:config",
        "--add-data",
        f"{ROOT / 'config' / 'noise_rules.example.json'}:config",
        "--hidden-import",
        "uvicorn.logging",
        "--hidden-import",
        "uvicorn.loops.auto",
        "--hidden-import",
        "uvicorn.protocols.http.auto",
        "--hidden-import",
        "uvicorn.protocols.websockets.auto",
        "--hidden-import",
        "uvicorn.lifespan.on",
        "--hidden-import",
        "anyio._backends._asyncio",
        "--hidden-import",
        "mcp.server.mcpserver",
        "--hidden-import",
        "mcp.server.mcpserver.tools",
        "--hidden-import",
        "mcp.server.mcpserver.utilities",
        str(ROOT / "scripts" / "nexa_entry.py"),
    ]
    subprocess.run(command, cwd=ROOT, check=True)

    built = ROOT / "dist" / executable_name("nexa")
    release_dir = ROOT / "release"
    release_dir.mkdir(exist_ok=True)
    target = release_dir / output_name
    shutil.copy2(built, target)
    if platform.system() != "Windows":
        target.chmod(0o755)
    print(target)


def release_asset_name() -> str:
    system = {
        "Darwin": "macos",
        "Linux": "linux",
        "Windows": "windows",
    }.get(platform.system(), platform.system().lower())
    machine = platform.machine().lower()
    arch = {"aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(machine, machine)
    suffix = ".exe" if platform.system() == "Windows" else ""
    return f"nexa-v{VERSION}-{system}-{arch}{suffix}"


def executable_name(name: str) -> str:
    return f"{name}.exe" if platform.system() == "Windows" else name


def _require_frontend_bundle() -> None:
    if not (ROOT / "web" / "dist" / "index.html").is_file():
        raise RuntimeError("web/dist is missing; run `npm --prefix web run build` first")


if __name__ == "__main__":
    main()
