#!/usr/bin/env python3
"""
Combine analysis results across languages into single files for unified analysis.

Merges per-language output files from the PrivLess pipeline and standalone tools
into combined files that can be loaded directly by the analysis notebooks.

Output files created:
  output/results/default_policy_analysis/combined_default_policy_stats.jsonl
  output/results/stats/combined_analysis_stats.jsonl
  output/results/stats/combined_analysis_stats-time.csv
"""

import os
import glob
import csv
import sys

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Project root: tools/ -> project_root/
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)


def _get_output_results_dir():
    """Resolve the results output directory from config.yaml."""
    config_path = os.path.join(_PROJECT_ROOT, "config.yaml")
    output_dir = "output"
    results_subdir = "results"
    if YAML_AVAILABLE and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
            output_dir = cfg.get("output", {}).get("dir", output_dir)
            results_subdir = cfg.get("output", {}).get("results_subdir", results_subdir)
        except Exception:
            pass
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(_PROJECT_ROOT, output_dir)
    return os.path.join(output_dir, results_subdir)


def combine_jsonl(input_pattern, output_path):
    """Concatenate multiple JSONL files matching a glob pattern into one."""
    files = sorted(glob.glob(input_pattern))
    if not files:
        print(f"  No files matching: {input_pattern}")
        return 0

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    total_lines = 0
    with open(output_path, "w") as out:
        for fpath in files:
            with open(fpath, "r") as inp:
                for line in inp:
                    stripped = line.strip()
                    if stripped:
                        out.write(stripped + "\n")
                        total_lines += 1
            print(f"  + {os.path.basename(fpath)} ({total_lines} lines so far)")

    print(f"  -> {output_path} ({total_lines} total lines)")
    return total_lines


def combine_csv(input_pattern, output_path, has_header=False):
    """Concatenate multiple CSV files matching a glob pattern into one.

    Args:
        input_pattern: Glob pattern for input files.
        output_path: Path for the combined output file.
        has_header: If True, first row of each file is a header.
                    The header from the first file is kept; headers from
                    subsequent files are skipped.
    """
    files = sorted(glob.glob(input_pattern))
    if not files:
        print(f"  No files matching: {input_pattern}")
        return 0

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    total_rows = 0
    header_written = False

    with open(output_path, "w", newline="") as out:
        for fpath in files:
            with open(fpath, "r", newline="") as inp:
                for i, line in enumerate(inp):
                    if has_header and i == 0:
                        if not header_written:
                            out.write(line)
                            header_written = True
                        continue
                    if line.strip():
                        out.write(line if line.endswith("\n") else line + "\n")
                        total_rows += 1
            print(f"  + {os.path.basename(fpath)} ({total_rows} rows so far)")

    print(f"  -> {output_path} ({total_rows} total rows)")
    return total_rows


def main():
    results_dir = _get_output_results_dir()
    print(f"Results directory: {results_dir}\n")

    # 1. Combine default policy analysis stats (per-language JSONL files)
    dpa_dir = os.path.join(results_dir, "default_policy_analysis")
    dpa_pattern = os.path.join(dpa_dir, "default_policy_stats_*.jsonl")
    dpa_output = os.path.join(dpa_dir, "combined_default_policy_stats.jsonl")
    print("=== Default Policy Analysis Stats ===")
    combine_jsonl(dpa_pattern, dpa_output)

    # 2. Combine PrivLess analysis stats (per-language subdirectories)
    stats_dir = os.path.join(results_dir, "stats")
    stats_pattern = os.path.join(stats_dir, "*", "analysis_stats.jsonl")
    stats_output = os.path.join(stats_dir, "combined_analysis_stats.jsonl")
    print("\n=== PrivLess Analysis Stats ===")
    combine_jsonl(stats_pattern, stats_output)

    # 3. Combine PrivLess runtime CSVs (per-language subdirectories, no headers)
    time_pattern = os.path.join(stats_dir, "*", "analysis_stats-time.csv")
    time_output = os.path.join(stats_dir, "combined_analysis_stats-time.csv")
    print("\n=== PrivLess Runtime Stats ===")
    combine_csv(time_pattern, time_output, has_header=False)

    print("\nDone.")


if __name__ == "__main__":
    main()
