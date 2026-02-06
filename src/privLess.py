#!/usr/bin/env python3
"""
PrivLess - Serverless IAM Privilege Analyzer.

Analyzes serverless applications using CodeQL to generate least-privilege
IAM policies. Supports JavaScript/TypeScript, Python, Go, and C#.
"""

import csv
import json
import os
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set

from utils.config import (
    load_config,
    LANGUAGE_MAP,
    get_output_dir,
    get_databases_dir,
    get_results_dir,
    get_policies_dir,
    get_stats_dir,
    ensure_directories,
)
from utils.log import setup_logger
from utils.codeql_agent import CodeQL
from utils.postprocess_truncated_values import process_csv
from privLess_extractor import ServiceExtractor
from privLess_resolver import ResourceResolver
from privLess_policyGenerator import PolicyGenerator

# Optional tqdm support
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class PrivLess:
    """Main orchestrator for serverless privilege analysis."""

    def __init__(self, cfg: Dict):
        """
        Initialize PrivLess from a loaded configuration dictionary.

        Args:
            cfg: Configuration dictionary (from load_config()).
        """
        self.cfg = cfg
        self.log = setup_logger("main", cfg)

        # Language settings
        self.language_key = cfg.get("analysis", {}).get("language", "javascript")
        self.language = LANGUAGE_MAP.get(self.language_key, "javascript-typescript")
        self.output_format = cfg.get("analysis", {}).get("output_format", "yaml").lower()

        # Paths (all resolved to absolute by config loader)
        self.apps_json_path = cfg["analysis"]["apps_json"]
        self.output_dir = get_output_dir(cfg)
        self.code_databases = get_databases_dir(cfg)
        self.results_path = get_results_dir(cfg)
        self.permission_map = cfg["data"]["permission_map"]

        # Stats
        self.stats_time_csv = os.path.join(
            get_stats_dir(cfg, self.language_key), "analysis_stats-time.csv"
        )

        # Ensure all output directories exist
        ensure_directories(cfg, self.language_key)

    def find_serverless_yaml(self, project_path: str):
        """Recursively find serverless.yml or serverless.yaml in a project."""
        for root, _, files in os.walk(project_path):
            for name in ("serverless.yml", "serverless.yaml"):
                if name in files:
                    self.log.info("Found %s at %s", name, root)
                    return os.path.join(root, name)
        self.log.warning("No serverless config found in %s", project_path)
        return None

    def _postprocess_js_ts_values(self, csv_path: str, source_root: str) -> str:
        """Post-process CodeQL CSV to resolve truncated JS/TS string values."""
        if not csv_path or not os.path.exists(csv_path):
            return csv_path
        if self.language != "javascript-typescript":
            return csv_path

        try:
            self.log.info("Post-processing truncated values: %s", os.path.basename(csv_path))
            total_rows, resolved_rows = process_csv(
                input_csv=csv_path,
                output_csv=csv_path,
                source_root=source_root,
                language="javascript-typescript",
                value_column="resourceValue",
                location_column="path",
            )
            if resolved_rows > 0:
                self.log.info("Resolved %d/%d truncated values.", resolved_rows, total_rows)
        except Exception as e:
            self.log.warning("Post-processing failed: %s", e)

        return csv_path

    # -- State management for resume --

    def _get_state_file_path(self):
        state_dir = get_stats_dir(self.cfg, self.language_key)
        os.makedirs(state_dir, exist_ok=True)
        return os.path.join(state_dir, "processing_state.json")

    def _load_processed_apps(self) -> Set[str]:
        state_file = self._get_state_file_path()
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    processed = set(state.get('processed_apps', []))
                    self.log.info("Loaded %d already-processed apps from state.", len(processed))
                    return processed
            except Exception as e:
                self.log.warning("Could not load state file: %s", e)
        return set()

    def _save_processed_app(self, app_name: str):
        state_file = self._get_state_file_path()
        lock_file = state_file + ".lock"

        for _ in range(50):
            try:
                fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except FileExistsError:
                time.sleep(0.1)
        else:
            self.log.warning("Could not acquire state file lock.")
            return

        try:
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state = json.load(f)
            else:
                state = {'processed_apps': []}

            if app_name not in state['processed_apps']:
                state['processed_apps'].append(app_name)
                state['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
                with open(state_file, 'w') as f:
                    json.dump(state, f, indent=2)
        finally:
            try:
                os.remove(lock_file)
            except OSError:
                pass

    def _reset_processed_apps(self):
        state_dir = get_stats_dir(self.cfg, self.language_key)
        for fname in ("processing_state.json", "analysis_stats.jsonl", "analysis_stats-time.csv"):
            fpath = os.path.join(state_dir, fname)
            if os.path.exists(fpath):
                os.remove(fpath)
                self.log.info("Cleared %s", fname)

    # -- Per-app processing --

    def _save_app_stat_data(self, app_stats: Dict):
        os.makedirs(os.path.dirname(self.stats_time_csv), exist_ok=True)
        write_header = not os.path.exists(self.stats_time_csv) or os.path.getsize(self.stats_time_csv) == 0
        with open(self.stats_time_csv, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=app_stats.keys())
            if write_header:
                writer.writeheader()
            writer.writerow(app_stats)

    def _process_single_app(
        self, app, codeql, service_extractor, resource_resolver,
        stats_file, stats_lock,
    ) -> Dict:
        """Process a single application through the full pipeline."""
        app_name = os.path.basename(app).strip('/')
        app_stats = {
            "app": app, "status": "failed",
            "db_time": None, "s_q_time": None, "r_q_time": None, "a_time": None,
        }

        try:
            serverless_yaml = self.find_serverless_yaml(app)
            if not serverless_yaml:
                app_stats["status"] = "no_serverless"
                with stats_lock:
                    self._save_app_stat_data(app_stats)
                return app_stats

            db_path = os.path.join(self.code_databases, self.language_key, f"db_{app_name}")

            # 1. Create CodeQL database
            created, runtime = codeql.create_database(app_name, app, db_path)
            if not created:
                app_stats["status"] = "db_failed"
                with stats_lock:
                    self._save_app_stat_data(app_stats)
                return app_stats
            app_stats["db_time"] = runtime

            # 2. Extract service calls
            service_calls_results, runtime = service_extractor.extract_service_calls(app_name, db_path)
            if not service_calls_results:
                app_stats["status"] = "query_failed"
                with stats_lock:
                    self._save_app_stat_data(app_stats)
                return app_stats
            app_stats["s_q_time"] = runtime

            # Post-process for JS/TS
            if self.language == "javascript-typescript":
                service_calls_results = self._postprocess_js_ts_values(service_calls_results, app)

            # 3. Run data-flow analysis
            resource_resolution_results, runtime = resource_resolver.run_data_flow_analysis(app_name, db_path)
            if not resource_resolution_results:
                app_stats["status"] = "query_failed"
                with stats_lock:
                    self._save_app_stat_data(app_stats)
                return app_stats
            app_stats["r_q_time"] = runtime

            if self.language == "javascript-typescript":
                resource_resolution_results = self._postprocess_js_ts_values(resource_resolution_results, app)

            # 4. Resolve resources
            start = time.perf_counter()
            resource_resolver.resolve_resources(
                service_calls_results, resource_resolution_results, serverless_yaml, show_summary=False
            )
            resolved_values = resource_resolver.get_results()

            # 5. Generate policy
            empty_apps_file = os.path.join(
                get_stats_dir(self.cfg, self.language_key), "empty_apps.json"
            )
            policy_generator = PolicyGenerator(
                self.permission_map, stats_output_path=stats_file,
                empty_apps_path=empty_apps_file, cfg=self.cfg,
            )
            policy_generator.load_permission_map()

            file_ext = '.yml' if self.output_format == 'yaml' else '.json'
            policy_output = os.path.join(
                get_policies_dir(self.cfg, self.language_key),
                f"{app_name}_policy{file_ext}",
            )
            os.makedirs(os.path.dirname(policy_output), exist_ok=True)

            policy_generator.generate_policy_file(
                app_name, resolved_values, output_file=policy_output,
                region="REGION", account="ACCOUNT", per_function=True,
                output_format=self.output_format, collect_stats=True, app_path=app,
            )

            with stats_lock:
                policy_generator.save_stats()

            app_stats["a_time"] = time.perf_counter() - start
            app_stats["status"] = "completed"

            with stats_lock:
                self._save_app_stat_data(app_stats)

            self._save_processed_app(app)
            self.log.info("Completed analysis for %s", app)
            return app_stats

        except Exception as e:
            self.log.error("Error processing %s: %s", app, e, exc_info=True)
            app_stats["status"] = "error"
            with stats_lock:
                self._save_app_stat_data(app_stats)
            return app_stats

    # -- Main analysis entry point --

    def analyze_projects(self, max_workers: int = 4, resume: bool = True, force_reprocess: bool = False):
        """
        Analyze all projects listed in the apps JSON file.

        Args:
            max_workers: Number of concurrent workers.
            resume: If True, skip already-processed apps.
            force_reprocess: If True, clear state and reprocess everything.
        """
        if not os.path.exists(self.apps_json_path):
            raise FileNotFoundError(f"Apps JSON file not found: {self.apps_json_path}")

        self.log.info("Language: %s (%s)", self.language_key, self.language)
        self.log.info("Apps JSON: %s", self.apps_json_path)
        self.log.info("Output dir: %s", self.output_dir)
        self.log.info("Workers: %d | Resume: %s", max_workers, resume)

        # Resume state
        if force_reprocess:
            self._reset_processed_apps()
            processed_apps = set()
        else:
            processed_apps = self._load_processed_apps() if resume else set()

        dataset_stats = {
            "completed": [], "no_serverless": [], "db_failed": [],
            "query_failed": [], "error": [], "skipped": [],
        }

        # Initialize components
        codeql = CodeQL(self.cfg, self.language_key, self.results_path)
        codeql.verify_codeql_queries()

        service_extractor = ServiceExtractor(codeql, self.language_key, self.cfg)
        resource_resolver = ResourceResolver(codeql, self.results_path, cfg=self.cfg)

        stats_file = os.path.join(
            get_stats_dir(self.cfg, self.language_key), "analysis_stats.jsonl"
        )
        stats_lock = threading.Lock()

        # Load apps
        with open(self.apps_json_path, 'r') as f:
            all_apps = json.load(f)

        apps_to_process = []
        for app in all_apps:
            if app in processed_apps:
                self.log.info("[Resume] Skipping: %s", app)
                dataset_stats["skipped"].append(app)
            else:
                apps_to_process.append(app)

        self.log.info("Total: %d | Already processed: %d | To process: %d",
                      len(all_apps), len(processed_apps), len(apps_to_process))

        if not apps_to_process:
            self.log.info("No apps to process. All done.")
            return dataset_stats

        start_time = time.perf_counter()
        total_apps = len(apps_to_process)
        completed_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_app = {
                executor.submit(
                    self._process_single_app, app, codeql,
                    service_extractor, resource_resolver, stats_file, stats_lock,
                ): app for app in apps_to_process
            }

            if TQDM_AVAILABLE:
                progress_bar = tqdm(total=total_apps, desc="Processing apps", unit="app")

            for future in as_completed(future_to_app):
                app = future_to_app[future]
                try:
                    app_stats = future.result()
                    status = app_stats["status"]
                    if status in dataset_stats:
                        dataset_stats[status].append(app)
                    completed_count += 1

                    if TQDM_AVAILABLE:
                        elapsed = time.perf_counter() - start_time
                        avg = elapsed / completed_count
                        eta = avg * (total_apps - completed_count)
                        progress_bar.set_postfix(
                            app=app[:30], status=status,
                            elapsed=f'{elapsed:.1f}s', ETA=f'{eta:.1f}s',
                        )
                        progress_bar.update(1)
                    else:
                        pct = (completed_count / total_apps) * 100
                        self.log.info("[%d/%d] (%.1f%%) %s - %s",
                                      completed_count, total_apps, pct, app, status)

                except Exception as e:
                    self.log.error("Exception for %s: %s", app, e)
                    dataset_stats["error"].append(app)
                    completed_count += 1
                    if TQDM_AVAILABLE:
                        progress_bar.update(1)

            if TQDM_AVAILABLE:
                progress_bar.close()

        total_time = time.perf_counter() - start_time
        self.log.info("="*60)
        self.log.info("ANALYSIS COMPLETE in %.2fs", total_time)
        self.log.info("Completed: %d | Skipped: %d | No serverless: %d | DB failed: %d | Query failed: %d | Errors: %d",
                      len(dataset_stats['completed']), len(dataset_stats['skipped']),
                      len(dataset_stats['no_serverless']), len(dataset_stats['db_failed']),
                      len(dataset_stats['query_failed']), len(dataset_stats['error']))
        self.log.info("="*60)

        return dataset_stats


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PrivLess - Serverless IAM Privilege Analyzer using CodeQL.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Analyze JavaScript apps with default config
  python privLess.py

  # Specify language and apps list
  python privLess.py --language python --apps-json apps/python_apps.json

  # Custom output directory and YAML format
  python privLess.py --output-dir ./my_output --output-format yaml

  # Use a custom config file
  python privLess.py --config /path/to/config.yaml

  # Force reprocess all apps
  python privLess.py --force-reprocess
""",
    )
    parser.add_argument("--config", default=None,
                        help="Path to config.yaml (default: <project_root>/config.yaml).")
    parser.add_argument("--language", choices=LANGUAGE_MAP.keys(), default=None,
                        help="Override language from config.")
    parser.add_argument("--apps-json", default=None,
                        help="Override apps JSON path from config.")
    parser.add_argument("--output-dir", default=None,
                        help="Override output directory from config.")
    parser.add_argument("--workers", type=int, default=None,
                        help="Override number of concurrent workers.")
    parser.add_argument("--resume", action="store_true", default=None,
                        help="Resume from previous run (default from config).")
    parser.add_argument("--no-resume", dest="resume", action="store_false",
                        help="Do not resume, process all apps.")
    parser.add_argument("--force-reprocess", action="store_true",
                        help="Clear state and reprocess everything.")
    parser.add_argument("--output-format", choices=["json", "yaml"], default=None,
                        help="Override output format from config.")

    args = parser.parse_args()

    # Load config
    cfg = load_config(args.config)

    # Apply CLI overrides
    if args.language:
        cfg.setdefault("analysis", {})["language"] = args.language
    if args.apps_json:
        cfg.setdefault("analysis", {})["apps_json"] = os.path.abspath(args.apps_json)
    if args.output_dir:
        cfg.setdefault("output", {})["dir"] = os.path.abspath(args.output_dir)
    if args.workers is not None:
        cfg.setdefault("analysis", {})["workers"] = args.workers
    if args.output_format:
        cfg.setdefault("analysis", {})["output_format"] = args.output_format

    # Build analyzer
    analyzer = PrivLess(cfg)

    # Resolve settings
    max_workers = cfg.get("analysis", {}).get("workers", 4)
    resume = args.resume if args.resume is not None else cfg.get("analysis", {}).get("resume", True)

    analyzer.analyze_projects(
        max_workers=max_workers,
        resume=resume,
        force_reprocess=args.force_reprocess,
    )


if __name__ == "__main__":
    main()
