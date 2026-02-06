#!/usr/bin/env python3
"""
Service call extractor for PrivLess.

Runs the CodeQL service-extraction query and returns the CSV output path.
"""

import os
import subprocess
import time
from typing import Dict, Any, Optional, Tuple

from utils.log import setup_logger


class ServiceExtractor:
    """Extracts AWS service calls from source code using CodeQL."""

    def __init__(self, codeql, language: str, cfg: Dict[str, Any]):
        """
        Args:
            codeql: CodeQL agent instance.
            language: User-facing language key.
            cfg: Loaded configuration dictionary.
        """
        self.codeql = codeql
        self.language = language
        self.query_type = "extractor"
        self.log = setup_logger("extractor", cfg)

    def extract_service_calls(
        self, app: str, app_db_path: str
    ) -> Tuple[Optional[str], Optional[float]]:
        """
        Run the extractor query on a CodeQL database.

        Args:
            app: Application name.
            app_db_path: Path to the CodeQL database.

        Returns:
            (csv_path, elapsed_seconds) or (None, None) on failure.
        """
        start = time.perf_counter()
        try:
            output = self.codeql.run_query(
                query_type=self.query_type,
                project_name=app,
                project_db_path=app_db_path,
            )

            if output and os.path.exists(output):
                elapsed = time.perf_counter() - start
                self.log.info("Service calls extracted for %s -> %s", app, output)
                return (output, elapsed)
            else:
                self.log.warning("Service call extraction produced no output for %s.", app)
                return (None, None)

        except subprocess.CalledProcessError as e:
            self.log.error("CodeQL query error for %s: %s", app_db_path, e)
            return (None, None)
        except Exception as e:
            self.log.error("Unexpected error during extraction for %s: %s", app, e)
            return (None, None)
