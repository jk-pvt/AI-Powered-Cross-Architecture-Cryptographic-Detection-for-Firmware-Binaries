"""Logging configuration for OpenCryptoDetect."""

import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure structured console logging using Rich."""
    logger = logging.getLogger("opencryptodetect")
    logger.handlers.clear()

    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logger.setLevel(level)

    handler = RichHandler(
        console=console,
        show_time=False,
        show_path=verbose,
        rich_tracebacks=verbose,
        tracebacks_show_locals=verbose,
    )
    handler.setLevel(level)
    logger.addHandler(handler)
    return logger


def get_logger() -> logging.Logger:
    """Retrieve default logger instance."""
    return logging.getLogger("opencryptodetect")
