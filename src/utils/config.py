#!/usr/bin/env python3
"""
Configuration loader for PrivLess.

Loads settings from config.yaml and resolves all paths relative to the project root.
"""

import os
import yaml
from typing import Any, Dict, Optional


# Project root is the parent of the src/ directory
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Language mapping: user-facing name -> CodeQL language identifier
LANGUAGE_MAP = {
    "javascript": "javascript-typescript",
    "typescript": "javascript-typescript",
    "python": "python",
    "go": "go",
    "csharp": "csharp",
}


def get_project_root() -> str:
    """Return the absolute path to the project root directory."""
    return _PROJECT_ROOT


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.

    Args:
        config_path: Path to config file. If None, uses <project_root>/config.yaml.

    Returns:
        Dictionary of configuration values with paths resolved to absolute paths.
    """
    if config_path is None:
        config_path = os.path.join(_PROJECT_ROOT, "config.yaml")

    if not os.path.isabs(config_path):
        config_path = os.path.join(_PROJECT_ROOT, config_path)

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    # Resolve relative paths to absolute, anchored at project root
    cfg = _resolve_paths(cfg)

    return cfg


def _resolve_paths(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve relative paths in the config to absolute paths."""
    root = _PROJECT_ROOT

    # -- output.dir --
    output_dir = cfg.get("output", {}).get("dir", "output")
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(root, output_dir)
    cfg.setdefault("output", {})["dir"] = output_dir

    # -- data.permission_map --
    pmap = cfg.get("data", {}).get("permission_map", "data/iam_service_actions.json")
    if not os.path.isabs(pmap):
        pmap = os.path.join(root, pmap)
    cfg.setdefault("data", {})["permission_map"] = pmap

    # -- analysis.apps_json --
    apps = cfg.get("analysis", {}).get("apps_json", "apps.json")
    if not os.path.isabs(apps):
        apps = os.path.join(root, apps)
    cfg.setdefault("analysis", {})["apps_json"] = apps

    return cfg


def get_output_dir(cfg: Dict[str, Any]) -> str:
    """Return the resolved base output directory."""
    return cfg["output"]["dir"]


def get_databases_dir(cfg: Dict[str, Any]) -> str:
    sub = cfg.get("output", {}).get("databases_subdir", "databases")
    return os.path.join(get_output_dir(cfg), sub)


def get_results_dir(cfg: Dict[str, Any]) -> str:
    sub = cfg.get("output", {}).get("results_subdir", "results")
    return os.path.join(get_output_dir(cfg), sub)


def get_policies_dir(cfg: Dict[str, Any], language: str) -> str:
    sub = cfg.get("output", {}).get("policies_subdir", "policies")
    return os.path.join(get_results_dir(cfg), sub, language)


def get_stats_dir(cfg: Dict[str, Any], language: str) -> str:
    codeql_lang = LANGUAGE_MAP.get(language, language)
    sub = cfg.get("output", {}).get("stats_subdir", "stats")
    return os.path.join(get_results_dir(cfg), sub, codeql_lang)


def get_logs_dir(cfg: Dict[str, Any]) -> str:
    sub = cfg.get("output", {}).get("logs_subdir", "logs")
    return os.path.join(get_output_dir(cfg), sub)


def get_codeql_executable(cfg: Dict[str, Any]) -> str:
    """Return the CodeQL executable path. Defaults to 'codeql' if empty."""
    exe = cfg.get("codeql", {}).get("executable", "").strip()
    return exe if exe else "codeql"


def ensure_directories(cfg: Dict[str, Any], language: str) -> None:
    """Create all required output directories."""
    codeql_lang = LANGUAGE_MAP.get(language, language)
    dirs = [
        get_output_dir(cfg),
        get_databases_dir(cfg),
        os.path.join(get_databases_dir(cfg), language),
        get_results_dir(cfg),
        get_policies_dir(cfg, language),
        get_stats_dir(cfg, language),
        get_logs_dir(cfg),
        # CodeQL query result subdirectories
        os.path.join(get_results_dir(cfg), "service_calls", language),
        os.path.join(get_results_dir(cfg), "resolved_resources", language),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
