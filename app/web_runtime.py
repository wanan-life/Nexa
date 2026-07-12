from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class WebBuildError(RuntimeError):
    """Raised when the bundled Web frontend cannot be prepared."""


def frontend_dist(project_root: Path) -> Path:
    return project_root / "web" / "dist"


def frontend_is_ready(project_root: Path) -> bool:
    dist = frontend_dist(project_root)
    return (dist / "index.html").is_file() and (dist / "assets").is_dir()


def ensure_frontend_bundle(project_root: Path, rebuild: bool = False) -> bool:
    """Build the frontend when absent or explicitly requested.

    Returns True when a new bundle was generated.
    """

    if frontend_is_ready(project_root) and not rebuild:
        return False

    web_dir = project_root / "web"
    package_json = web_dir / "package.json"
    if not package_json.is_file():
        raise WebBuildError(f"Web source directory is incomplete: {package_json}")

    npm = shutil.which("npm")
    if not npm:
        raise WebBuildError(
            "npm is required only for the first Web build. Install Node.js/npm and rerun `nexa web`."
        )

    if not (web_dir / "node_modules").is_dir():
        install_command = [npm, "ci"] if (web_dir / "package-lock.json").is_file() else [npm, "install"]
        _run(install_command, web_dir, "install frontend dependencies")

    _run([npm, "run", "build"], web_dir, "build the Web frontend")
    if not frontend_is_ready(project_root):
        raise WebBuildError("Frontend build completed without producing web/dist/index.html")
    return True


def _run(command: list[str], cwd: Path, action: str) -> None:
    try:
        subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or exc.stdout or "unknown npm error").strip()
        raise WebBuildError(f"Failed to {action}: {details[-2000:]}") from exc
