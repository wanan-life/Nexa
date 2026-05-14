from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

SUBFINDER_VERSION = "2.14.0"
HTTPX_VERSION = "1.9.0"
ONEFORALL_REPO = "https://github.com/shmilylty/OneForAll.git"


@dataclass(frozen=True)
class DetectedPlatform:
    os_token: str
    arch_token: str
    executable_suffix: str = ""


def detect_platform() -> DetectedPlatform:
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {
        "darwin": ("macOS", ""),
        "linux": ("linux", ""),
        "windows": ("windows", ".exe"),
    }
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "i386": "386",
        "i686": "386",
    }

    if system not in os_map:
        raise RuntimeError(f"Unsupported OS for bundled tool bootstrap: {platform.system()}")
    if machine not in arch_map:
        raise RuntimeError(f"Unsupported CPU architecture for bundled tool bootstrap: {platform.machine()}")

    os_token, suffix = os_map[system]
    return DetectedPlatform(os_token=os_token, arch_token=arch_map[machine], executable_suffix=suffix)


def projectdiscovery_release_url(tool: str, version: str, detected: DetectedPlatform) -> str:
    return (
        f"https://github.com/projectdiscovery/{tool}/releases/download/"
        f"v{version}/{tool}_{version}_{detected.os_token}_{detected.arch_token}.zip"
    )


def bootstrap_tools(
    root: Path | None = None,
    include_subfinder: bool = True,
    include_httpx: bool = True,
    include_oneforall: bool = True,
) -> None:
    project_root = root or ROOT
    tools_dir = project_root / "tools"
    detected = detect_platform()
    tools_dir.mkdir(parents=True, exist_ok=True)

    if include_subfinder:
        install_zip_tool(
            tools_dir,
            "subfinder",
            projectdiscovery_release_url("subfinder", SUBFINDER_VERSION, detected),
            f"subfinder{detected.executable_suffix}",
        )
    if include_httpx:
        install_zip_tool(
            tools_dir,
            "httpx",
            projectdiscovery_release_url("httpx", HTTPX_VERSION, detected),
            f"httpx{detected.executable_suffix}",
        )
    if include_oneforall:
        install_oneforall(tools_dir, detected)

    print("Tool bootstrap completed.")


def main() -> None:
    bootstrap_tools()


def install_zip_tool(tools_dir: Path, name: str, url: str, binary_name: str) -> None:
    target_dir = tools_dir / name
    binary_path = target_dir / binary_name
    if binary_path.exists():
        print(f"{name}: already installed at {binary_path}")
        return

    target_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        zip_path = tmp_dir / f"{name}.zip"
        print(f"{name}: downloading {url}")
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(tmp_dir)
        found = _find_binary(tmp_dir, binary_name)
        if not found:
            raise RuntimeError(f"{name}: binary {binary_name} not found in archive")
        shutil.copy2(found, binary_path)

    binary_path.chmod(0o755)
    if name == "subfinder":
        ensure_file(target_dir / "config.yaml", "{}\n")
        ensure_file(target_dir / "provider-config.yaml", "{}\n")
    print(f"{name}: installed at {binary_path}")


def _find_binary(root: Path, binary_name: str) -> Path | None:
    exact = next(root.rglob(binary_name), None)
    if exact:
        return exact
    stem = Path(binary_name).stem
    for candidate in root.rglob("*"):
        if candidate.is_file() and candidate.stem == stem:
            return candidate
    return None


def ensure_file(path: Path, content: str) -> None:
    if not path.exists():
        path.write_text(content, encoding="utf-8")


def install_oneforall(tools_dir: Path, detected: DetectedPlatform) -> None:
    target_dir = tools_dir / "OneForAll"
    if not target_dir.exists():
        print(f"OneForAll: cloning {ONEFORALL_REPO}")
        subprocess.run(["git", "clone", "--depth", "1", ONEFORALL_REPO, str(target_dir)], check=True)
    else:
        print(f"OneForAll: already present at {target_dir}")

    requirements = target_dir / "requirements.txt"
    if not requirements.exists():
        print("OneForAll: requirements.txt not found, skipping dependency install")
        return

    venv_python = _oneforall_venv_python(target_dir, detected)
    if not venv_python.exists():
        print("OneForAll: creating local virtualenv")
        subprocess.run([sys.executable, "-m", "venv", str(target_dir / ".venv")], check=True)

    print("OneForAll: installing dependencies")
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-r", str(requirements)],
        cwd=str(target_dir),
        check=False,
    )
    print("OneForAll: applying fire compatibility fix")
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "fire>=0.7.0"],
        cwd=str(target_dir),
        check=False,
    )


def _oneforall_venv_python(target_dir: Path, detected: DetectedPlatform) -> Path:
    if detected.executable_suffix:
        return target_dir / ".venv" / "Scripts" / "python.exe"
    return target_dir / ".venv" / "bin" / "python"


if __name__ == "__main__":
    main()
