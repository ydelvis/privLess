#!/usr/bin/env python3
"""
CodeQL agent for PrivLess.

Handles CodeQL database creation and query execution.
"""

import os
import subprocess
import time
from typing import Dict, Any, Tuple

from utils.config import get_project_root, get_codeql_executable, LANGUAGE_MAP
from utils.log import setup_logger


class CodeQL:
    """Manages CodeQL database creation and query execution."""

    QUERY_TYPE = {
        "extractor": "service_calls",
        "resolver": "resolved_resources",
    }

    def __init__(self, cfg: Dict[str, Any], language: str, results_path: str):
        """
        Initialize CodeQL agent.

        Args:
            cfg: Loaded configuration dictionary.
            language: User-facing language key (e.g. "javascript", "python").
            results_path: Absolute path for storing query results.
        """
        self.cfg = cfg
        self.language = language
        self.results_path = results_path
        self.codeql_executable = get_codeql_executable(cfg)
        self.log = setup_logger("codeql", cfg)

        # Query directory is always <project_root>/queries/<codeql_lang>
        project_root = get_project_root()
        codeql_lang = self._get_language_for_queries(language)
        self.query_path = os.path.join(project_root, "queries", codeql_lang)
        self.extractor_query_file = os.path.join(self.query_path, "requestExtractor.ql")
        self.resolver_query_file = os.path.join(self.query_path, "resourceResolver.ql")

    @staticmethod
    def _get_language_for_queries(language: str) -> str:
        """Map user language key to the query directory name."""
        if language.lower() in ("javascript", "typescript"):
            return "javascript-typescript"
        return language

    def verify_codeql_queries(self) -> None:
        """Verify that required query files exist. Exits on failure."""
        if not os.path.isfile(self.extractor_query_file):
            self.log.error("Extractor query not found for '%s': %s", self.language, self.extractor_query_file)
            raise FileNotFoundError(f"Extractor query not found: {self.extractor_query_file}")

        if not os.path.isfile(self.resolver_query_file):
            self.log.error("Resolver query not found for '%s': %s", self.language, self.resolver_query_file)
            raise FileNotFoundError(f"Resolver query not found: {self.resolver_query_file}")

        self.log.info("All CodeQL query files verified for language '%s'.", self.language)

    def install_dependencies(self) -> None:
        """Install CodeQL query pack dependencies if not already present."""
        lock_file = os.path.join(os.path.dirname(self.extractor_query_file), "codeql-pack.lock.yml")

        if os.path.isfile(lock_file):
            self.log.info("CodeQL query dependencies already installed.")
            return

        cmd = f"cd {os.path.dirname(self.extractor_query_file)} && {self.codeql_executable} pack install"
        self.log.info("Installing query dependencies: %s", cmd)
        result = os.system(cmd)
        if result != 0:
            self.log.error("Failed to install CodeQL query dependencies for '%s'.", self.language)
            raise RuntimeError(f"CodeQL pack install failed for language '{self.language}'")

        self.log.info("CodeQL query dependencies installed.")

    def create_database(self, project_name: str, project_path: str, db_path: str) -> Tuple[bool, float]:
        """
        Create a CodeQL database for a project.

        Returns:
            (success, elapsed_seconds)
        """
        start = time.perf_counter()
        codeql_lang = LANGUAGE_MAP.get(self.language, self.language)

        if os.path.exists(db_path):
            self.log.info("Database already exists for %s at %s. Skipping.", project_name, db_path)
            return (True, time.perf_counter() - start)

        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        cmd = (
            f"{self.codeql_executable} database create {db_path} "
            f"--overwrite -l {codeql_lang} --source-root={project_path}"
        )
        self.log.info("Creating database for %s: %s", project_name, cmd)
        result = os.system(cmd)

        if result == 0:
            self.log.info("Database created for %s.", project_name)
            return (True, time.perf_counter() - start)
        else:
            self.log.error("Database creation failed for %s.", project_name)
            return (False, None)

    def run_query(self, query_type: str, project_name: str, project_db_path: str) -> str:
        """
        Run a CodeQL query and return the path to the resulting CSV.

        Args:
            query_type: "extractor" or "resolver".
            project_name: Name of the project being analyzed.
            project_db_path: Path to the CodeQL database.

        Returns:
            Path to the output CSV file, or None on failure.
        """
        output_bqrs = os.path.join(
            self.results_path,
            self.QUERY_TYPE[query_type],
            self.language,
            f"{project_name}.bqrs",
        )
        output_csv = output_bqrs.replace(".bqrs", ".csv")
        os.makedirs(os.path.dirname(output_bqrs), exist_ok=True)

        if os.path.exists(output_csv):
            self.log.info("Query results already exist for %s at %s. Skipping.", project_name, output_csv)
            return output_csv

        self.log.info("Running %s %s query for %s ...", self.language, query_type, project_name)

        if query_type == "extractor":
            query = self.extractor_query_file
        elif query_type == "resolver":
            query = self.resolver_query_file
        else:
            self.log.error("Unknown query type: %s", query_type)
            return None

        try:
            query_pack_dir = os.path.dirname(query)
            query_cmd = (
                f"cd {query_pack_dir} && "
                f"{self.codeql_executable} query run {query} "
                f"--database {project_db_path} "
                f"--output {output_bqrs} "
                f"--search-path {query_pack_dir} "
                f"--verbose"
            )
            self.log.debug("Running: %s", query_cmd)
            os.system(query_cmd)
            self.log.info("Query executed: %s -> %s", query_type, output_bqrs)

            # Decode BQRS -> CSV
            decode_cmd = (
                f"{self.codeql_executable} bqrs decode "
                f"--format=csv {output_bqrs} "
                f"--output {output_csv}"
            )
            self.log.debug("Decoding: %s", decode_cmd)
            os.system(decode_cmd)
            self.log.info("Decoded results: %s", output_csv)

            return output_csv

        except subprocess.CalledProcessError as e:
            self.log.error("Error running CodeQL query on %s: %s", project_db_path, e)
            return None
        except Exception as e:
            self.log.error("Unexpected error during query execution: %s", e)
            return None
        finally:
            # Clean up BQRS to save space
            if os.path.exists(output_bqrs):
                os.remove(output_bqrs)
