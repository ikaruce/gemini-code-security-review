"""Logging utilities for Gemini Code Security Review."""

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                fmt="[%(levelname)s] %(name)s: %(message)s"
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
