"""Entry point for ``python -m app.mcp``."""

from __future__ import annotations

import argparse

from app.mcp.server import run_stdio


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Nexa MCP server over stdio.")
    parser.add_argument(
        "--allow-scan",
        action="store_true",
        help="Expose the scan_target tool, which runs bundled external recon tools.",
    )
    args = parser.parse_args()
    run_stdio(enable_scan=args.allow_scan)


if __name__ == "__main__":
    main()
