"""CLI entry point."""

from __future__ import annotations

import argparse
import sys

from sentinelpy._version import __version__
from sentinelpy.cli.exit_codes import EXIT_USAGE
from sentinelpy.cli.scan_cmd import add_scan_parser


def main(argv: list[str] | None = None) -> int:
    """Run the SentinelPy CLI."""

    parser = argparse.ArgumentParser(
        prog="sentinelpy",
        description=("Authorized, read-only HTTP security header checks for one URL."),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sentinelpy {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")
    add_scan_parser(subparsers)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
