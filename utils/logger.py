"""Structured logger backed by Rich for clean console output."""
from __future__ import annotations
import logging
from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)


def get_logger(name: str = "waf_analyzer", verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(message)s", datefmt="[%X]",
        handlers=[RichHandler(console=_console, rich_tracebacks=True,
                              show_path=False, markup=True)],
        force=True,
    )
    log = logging.getLogger(name)
    log.setLevel(level)
    return log


log = get_logger()
