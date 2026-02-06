#!/usr/bin/env python3
"""
Scan dataset/ for serverless apps and group them by language based on
the runtime field in serverless.yml/serverless.yaml.

Outputs one JSON file per language into the project root:
  apps_javascript.json, apps_python.json, apps_go.json
"""

import json
import os
import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")


def classify_runtime(runtime: str) -> str | None:
    """Map a serverless runtime string to a language key."""
    if not runtime or not isinstance(runtime, str):
        return None
    rt = runtime.lower().strip()
    if rt.startswith("node"):
        return "javascript"
    if rt.startswith("python"):
        return "python"
    if rt.startswith("go"):
        return "go"
    return None


def find_serverless_config(app_path: str) -> str | None:
    """Find serverless.yml or serverless.yaml in app_path (recursive)."""
    for root, _, files in os.walk(app_path):
        for name in ("serverless.yml", "serverless.yaml"):
            if name in files:
                return os.path.join(root, name)
    return None


def get_runtime(config_path: str) -> str | None:
    """Extract the runtime from a serverless config file."""
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
    except Exception:
        return None

    if not isinstance(cfg, dict):
        return None

    provider = cfg.get("provider")
    if isinstance(provider, dict):
        rt = provider.get("runtime")
        if rt:
            return str(rt)

        # Check function-level runtimes as fallback
        functions = cfg.get("functions", {})
        if isinstance(functions, dict):
            for fn_cfg in functions.values():
                if isinstance(fn_cfg, dict) and "runtime" in fn_cfg:
                    return str(fn_cfg["runtime"])

    return None


def main():
    apps_by_lang = {"javascript": [], "python": [], "go": []}
    skipped = []

    entries = sorted(os.listdir(DATASET_DIR))
    for entry in entries:
        app_path = os.path.join(DATASET_DIR, entry)
        if not os.path.isdir(app_path):
            continue

        config_path = find_serverless_config(app_path)
        if not config_path:
            skipped.append((entry, "no serverless config"))
            continue

        runtime = get_runtime(config_path)
        lang = classify_runtime(runtime)
        if lang is None:
            skipped.append((entry, f"unknown runtime: {runtime}"))
            continue

        # Store path relative to project root (e.g. "dataset/privLess_app_050")
        rel_path = os.path.relpath(app_path, PROJECT_ROOT)
        apps_by_lang[lang].append(rel_path)

    # Write output files into project root
    for lang, apps in apps_by_lang.items():
        out_path = os.path.join(PROJECT_ROOT, f"apps_{lang}.json")
        with open(out_path, "w") as f:
            json.dump(apps, f, indent=2)
        print(f"{lang}: {len(apps)} apps -> {out_path}")

    if skipped:
        print(f"\nSkipped {len(skipped)} apps:")
        for name, reason in skipped:
            print(f"  {name}: {reason}")


if __name__ == "__main__":
    main()
