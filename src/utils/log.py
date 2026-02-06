#!/usr/bin/env python3
"""
Logging setup for PrivLess.

Provides per-module file loggers so each key service writes to its own log file.
"""

import logging
import os
from typing import Any, Dict, Optional


_LOGGERS: Dict[str, logging.Logger] = {}


def setup_logger(
    name: str,
    cfg: Dict[str, Any],
    log_filename: Optional[str] = None,
) -> logging.Logger:
    """
    Create (or return existing) a named logger that writes to a file.

    Args:
        name: Logger name (e.g. "codeql", "extractor").
        cfg: Loaded configuration dictionary.
        log_filename: Override log file name. If None, uses cfg -> logging.files.<name>.

    Returns:
        Configured logging.Logger instance.
    """
    if name in _LOGGERS:
        return _LOGGERS[name]

    # Determine log directory and file
    logs_subdir = cfg.get("output", {}).get("logs_subdir", "logs")
    logs_dir = os.path.join(cfg.get("output", {}).get("dir", "output"), logs_subdir)
    os.makedirs(logs_dir, exist_ok=True)

    if log_filename is None:
        log_filename = cfg.get("logging", {}).get("files", {}).get(name, f"{name}.log")

    log_path = os.path.join(logs_dir, log_filename)

    # Log level
    level_name = cfg.get("logging", {}).get("level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    # Create logger
    logger = logging.getLogger(f"privless.{name}")
    logger.setLevel(level)
    logger.propagate = False  # Prevent duplicate output

    # File handler
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == os.path.abspath(log_path) for h in logger.handlers):
        fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        fh.setLevel(level)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    # Optional console handler
    console_output = cfg.get("logging", {}).get("console_output", True)
    if console_output:
        if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in logger.handlers):
            ch = logging.StreamHandler()
            ch.setLevel(level)
            fmt_console = logging.Formatter("[%(levelname)s] %(message)s")
            ch.setFormatter(fmt_console)
            logger.addHandler(ch)

    _LOGGERS[name] = logger
    return logger
