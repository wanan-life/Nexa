from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

SUBFINDER_URL = (
    "https://github.com/projectdiscovery/subfinder/releases/download/"
    "v2.14.0/subfinder_2.14.0_macOS_arm64.zip"
)
HTTPX_URL = (
    "https://github.com/projectdiscovery/httpx/releases/download/"
    "v1.9.0/httpx_1.9.0_macOS_arm64.zip"
)
ONEFORALL_REPO = "https://github.com/shmilylty/OneForAll.git"


def main() -> None:
    TOOLS.mkdir(parents=True, exist_ok=True)
    install_zip_tool("subfinder", SUBFINDER_URL, "subfinder")
    install_zip_tool("httpx", HTTPX_URL, "httpx")
    install_oneforall()
    print("Tool bootstrap completed.")


def install_zip_tool(name: str, url: str, binary_name: str) -> None:
    target_dir = TOOLS / name
    binary_path = target_dir / binary_name
    if binary_path.exists():
        print(f"{name}: already installed at {binary_path}")
        return

    target_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / f"{name}.zip"
        print(f"{name}: downloading {url}")
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(tmp)
        found = next(Path(tmp).rglob(binary_name), None)
        if not found:
            raise RuntimeError(f"{name}: binary {binary_name} not found in archive")
        shutil.copy2(found, binary_path)
    binary_path.chmod(0o755)
    if name == "subfinder":
        ensure_file(target_dir / "config.yaml", "{}\n")
        ensure_file(target_dir / "provider-config.yaml", "{}\n")
    print(f"{name}: installed at {binary_path}")


def ensure_file(path: Path, content: str) -> None:
    if not path.exists():
        path.write_text(content, encoding="utf-8")


def install_oneforall() -> None:
    target_dir = TOOLS / "OneForAll"
    if not target_dir.exists():
        print(f"OneForAll: cloning {ONEFORALL_REPO}")
        subprocess.run(["git", "clone", "--depth", "1", ONEFORALL_REPO, str(target_dir)], check=True)
    else:
        print(f"OneForAll: already present at {target_dir}")

    requirements = target_dir / "requirements.txt"
    if not requirements.exists():
        print("OneForAll: requirements.txt not found, skipping dependency install")
        return

    venv_python = target_dir / ".venv" / "bin" / "python"
    if not venv_python.exists():
        print("OneForAll: creating local virtualenv")
        subprocess.run([sys.executable, "-m", "venv", str(target_dir / ".venv")], check=True)

    print("OneForAll: installing dependencies")
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-r", str(requirements)],
        cwd=str(target_dir),
        check=False,
    )
    print("OneForAll: applying Python 3.13 fire compatibility fix")
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "fire>=0.7.0"],
        cwd=str(target_dir),
        check=False,
    )


if __name__ == "__main__":
    main()
