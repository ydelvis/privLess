#!/usr/bin/env python3
"""
Post-processing script to resolve truncated values from CodeQL output.

CodeQL may truncate long string values in its output. This script:
1. Reads CodeQL CSV output files
2. Parses file locations
3. Reads source files to extract full values
4. Outputs updated CSV with complete values

Supports: JavaScript, TypeScript, Python, Go
"""

import csv
import os
import re
import argparse
from typing import Dict, List, Optional, Tuple


class SourceValueExtractor:
    """Extracts full string values from source files based on CodeQL locations."""

    # Maximum characters to extract (safety limit)
    MAX_VALUE_LENGTH = 10000

    def __init__(self, source_root: str):
        """
        Initialize the extractor.

        Args:
            source_root: Root directory of the source code being analyzed
        """
        self.source_root = source_root
        self._file_cache: Dict[str, List[str]] = {}

    def _load_file(self, file_path: str) -> Optional[List[str]]:
        """Load and cache a source file."""
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        # Try both absolute and relative paths
        paths_to_try = [
            file_path,
            os.path.join(self.source_root, file_path),
        ]

        for path in paths_to_try:
            if os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.readlines()
                        self._file_cache[file_path] = lines
                        return lines
                except Exception as e:
                    print(f"Warning: Could not read file {path}: {e}")

        return None

    def parse_location(self, location: str) -> Optional[Tuple[str, int, int, int, int]]:
        """
        Parse a CodeQL location string.

        Formats:
        - file:line:col:endline:endcol
        - file:line:col
        - file://path:line:col:endline:endcol

        Returns: (file_path, start_line, start_col, end_line, end_col) or None
        """
        if not location:
            return None

        # Remove file:// prefix if present
        if location.startswith("file://"):
            location = location[7:]

        # Try full format: file:line:col:endline:endcol
        match = re.match(r'^(.+?):(\d+):(\d+):(\d+):(\d+)$', location)
        if match:
            return (
                match.group(1),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                int(match.group(5))
            )

        # Try short format: file:line:col
        match = re.match(r'^(.+?):(\d+):(\d+)$', location)
        if match:
            line = int(match.group(2))
            col = int(match.group(3))
            return (match.group(1), line, col, line, col + 100)  # Estimate end

        return None

    def extract_value_at_location(
        self,
        file_path: str,
        start_line: int,
        start_col: int,
        end_line: int,
        end_col: int,
        language: str = "javascript"
    ) -> Optional[str]:
        """
        Extract the full value from source code at the given location.

        Args:
            file_path: Path to the source file
            start_line: 1-indexed start line
            start_col: 1-indexed start column
            end_line: 1-indexed end line
            end_col: 1-indexed end column
            language: Programming language (javascript, typescript, python, go)

        Returns: The extracted value or None
        """
        lines = self._load_file(file_path)
        if not lines:
            return None

        # Convert to 0-indexed
        start_line_idx = start_line - 1
        end_line_idx = end_line - 1
        start_col_idx = start_col - 1
        end_col_idx = end_col - 1

        # Validate bounds
        if start_line_idx < 0 or start_line_idx >= len(lines):
            return None
        if end_line_idx < 0 or end_line_idx >= len(lines):
            end_line_idx = len(lines) - 1

        # Extract the text span
        if start_line_idx == end_line_idx:
            # Single line
            line = lines[start_line_idx]
            extracted = line[start_col_idx:end_col_idx + 1] if end_col_idx < len(line) else line[start_col_idx:]
        else:
            # Multi-line
            parts = []
            for i in range(start_line_idx, end_line_idx + 1):
                if i >= len(lines):
                    break
                line = lines[i]
                if i == start_line_idx:
                    parts.append(line[start_col_idx:])
                elif i == end_line_idx:
                    parts.append(line[:end_col_idx + 1])
                else:
                    parts.append(line)
            extracted = ''.join(parts)

        # Try to extract a complete string value
        extracted = extracted.strip()
        full_value = self._extract_string_value(extracted, language, lines, start_line_idx, start_col_idx)

        return full_value[:self.MAX_VALUE_LENGTH] if full_value else extracted[:self.MAX_VALUE_LENGTH]

    def _extract_string_value(
        self,
        text: str,
        language: str,
        lines: List[str],
        line_idx: int,
        col_idx: int
    ) -> Optional[str]:
        """
        Extract a complete string value, handling language-specific syntax.
        """
        # Get more context if needed
        context = self._get_extended_context(lines, line_idx, col_idx, 500)

        if language in ("javascript", "typescript", "javascript-typescript"):
            return self._extract_js_string(context)
        elif language == "python":
            return self._extract_python_string(context)
        elif language == "go":
            return self._extract_go_string(context)
        else:
            return self._extract_generic_string(context)

    def _get_extended_context(
        self,
        lines: List[str],
        start_line_idx: int,
        start_col_idx: int,
        max_chars: int
    ) -> str:
        """Get extended context from the source file."""
        result = []
        chars_collected = 0

        for i in range(start_line_idx, min(start_line_idx + 20, len(lines))):
            line = lines[i]
            if i == start_line_idx:
                line = line[start_col_idx:]
            result.append(line)
            chars_collected += len(line)
            if chars_collected >= max_chars:
                break

        return ''.join(result)

    def _extract_js_string(self, context: str) -> Optional[str]:
        """Extract JavaScript/TypeScript string values."""
        # Template literal
        match = re.match(r'^`([^`]*(?:\\.[^`]*)*)`', context, re.DOTALL)
        if match:
            return self._unescape_js_string(match.group(1))

        # Double-quoted string
        match = re.match(r'^"([^"\\]*(?:\\.[^"\\]*)*)"', context)
        if match:
            return self._unescape_js_string(match.group(1))

        # Single-quoted string
        match = re.match(r"^'([^'\\]*(?:\\.[^'\\]*)*)'", context)
        if match:
            return self._unescape_js_string(match.group(1))

        # Variable or expression - return as-is with marker
        match = re.match(r'^([a-zA-Z_$][a-zA-Z0-9_$]*)', context)
        if match:
            return "${" + match.group(1) + "}"

        return None

    def _extract_python_string(self, context: str) -> Optional[str]:
        """Extract Python string values."""
        # Triple-quoted strings (both variants)
        for quote in ['"""', "'''"]:
            if context.startswith(quote):
                end_idx = context.find(quote, 3)
                if end_idx != -1:
                    return context[3:end_idx]

        # f-string
        if context.startswith('f"') or context.startswith("f'"):
            quote = context[1]
            match = re.match(rf'^f{quote}([^{quote}\\]*(?:\\.[^{quote}\\]*)*){quote}', context)
            if match:
                return match.group(1)

        # Regular strings
        match = re.match(r'^"([^"\\]*(?:\\.[^"\\]*)*)"', context)
        if match:
            return match.group(1)

        match = re.match(r"^'([^'\\]*(?:\\.[^'\\]*)*)'", context)
        if match:
            return match.group(1)

        return None

    def _extract_go_string(self, context: str) -> Optional[str]:
        """Extract Go string values."""
        # Raw string literal
        match = re.match(r'^`([^`]*)`', context, re.DOTALL)
        if match:
            return match.group(1)

        # Interpreted string literal
        match = re.match(r'^"([^"\\]*(?:\\.[^"\\]*)*)"', context)
        if match:
            return self._unescape_go_string(match.group(1))

        return None

    def _extract_generic_string(self, context: str) -> Optional[str]:
        """Generic string extraction for unknown languages."""
        # Double-quoted
        match = re.match(r'^"([^"\\]*(?:\\.[^"\\]*)*)"', context)
        if match:
            return match.group(1)

        # Single-quoted
        match = re.match(r"^'([^'\\]*(?:\\.[^'\\]*)*)'", context)
        if match:
            return match.group(1)

        return None

    def _unescape_js_string(self, s: str) -> str:
        """Unescape JavaScript string escape sequences."""
        replacements = [
            (r'\\n', '\n'),
            (r'\\r', '\r'),
            (r'\\t', '\t'),
            (r'\\\\', '\\'),
            (r'\\"', '"'),
            (r"\\'", "'"),
            (r'\\`', '`'),
        ]
        result = s
        for pattern, replacement in replacements:
            result = result.replace(pattern.replace('\\\\', '\\'), replacement)
        return result

    def _unescape_go_string(self, s: str) -> str:
        """Unescape Go string escape sequences."""
        return self._unescape_js_string(s)  # Similar escaping rules


def process_csv(
    input_csv: str,
    output_csv: str,
    source_root: str,
    language: str,
    value_column: str = "resourceValue",
    location_column: str = "path",
    update_in_place: bool = True
) -> Tuple[int, int]:
    """
    Process a CodeQL CSV output file to resolve truncated values.

    Args:
        input_csv: Path to input CSV file
        output_csv: Path to output CSV file
        source_root: Root directory of source code
        language: Programming language
        value_column: Name of the column containing values to resolve
        location_column: Name of the column containing file locations
        update_in_place: If True, update the original column. If False, add a new column with '_full' suffix.

    Returns: (total_rows, resolved_rows) count
    """
    extractor = SourceValueExtractor(source_root)

    total_rows = 0
    resolved_rows = 0

    with open(input_csv, 'r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames

        if not fieldnames:
            print(f"Error: Could not read headers from {input_csv}")
            return (0, 0)

        # Add resolved value column if not updating in place and not already present
        if not update_in_place and f"{value_column}_full" not in fieldnames:
            fieldnames = list(fieldnames) + [f"{value_column}_full"]

        rows = []
        for row in reader:
            total_rows += 1

            location = row.get(location_column, "")
            current_value = row.get(value_column, "")

            # Check if value appears truncated (ends with ... or is very short but location spans more)
            needs_resolution = (
                current_value.endswith("...") or
                current_value.endswith("…") or
                "${" in current_value or
                len(current_value) < 10
            )

            resolved_value = current_value

            if needs_resolution and location:
                parsed = extractor.parse_location(location)
                if parsed:
                    file_path, start_line, start_col, end_line, end_col = parsed
                    extracted = extractor.extract_value_at_location(
                        file_path, start_line, start_col, end_line, end_col, language
                    )
                    if extracted and extracted != current_value:
                        resolved_value = extracted
                        resolved_rows += 1

            # Update the appropriate column
            if update_in_place:
                row[value_column] = resolved_value
            else:
                row[f"{value_column}_full"] = resolved_value

            rows.append(row)

    # Write output
    os.makedirs(os.path.dirname(output_csv) or '.', exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return (total_rows, resolved_rows)


def process_directory(
    input_dir: str,
    output_dir: str,
    source_root: str,
    language: str
) -> Dict[str, Tuple[int, int]]:
    """
    Process all CSV files in a directory.

    Returns: Dict mapping filename to (total_rows, resolved_rows)
    """
    results = {}

    for filename in os.listdir(input_dir):
        if filename.endswith('.csv'):
            input_path = os.path.join(input_dir, filename)
            output_path = os.path.join(output_dir, filename)

            print(f"Processing {filename}...")
            total, resolved = process_csv(
                input_path, output_path, source_root, language
            )
            results[filename] = (total, resolved)
            print(f"  Processed {total} rows, resolved {resolved} truncated values")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Resolve truncated values in CodeQL CSV output by reading source files"
    )
    parser.add_argument(
        "input",
        help="Input CSV file or directory containing CSV files"
    )
    parser.add_argument(
        "output",
        help="Output CSV file or directory"
    )
    parser.add_argument(
        "--source-root",
        required=True,
        help="Root directory of the source code being analyzed"
    )
    parser.add_argument(
        "--language",
        choices=["javascript", "typescript", "javascript-typescript", "python", "go"],
        default="javascript-typescript",
        help="Programming language (default: javascript-typescript)"
    )
    parser.add_argument(
        "--value-column",
        default="resourceValue",
        help="Name of the column containing values to resolve (default: resourceValue)"
    )
    parser.add_argument(
        "--location-column",
        default="path",
        help="Name of the column containing file locations (default: path)"
    )

    args = parser.parse_args()

    if os.path.isdir(args.input):
        os.makedirs(args.output, exist_ok=True)
        results = process_directory(
            args.input, args.output, args.source_root, args.language
        )
        total_files = len(results)
        total_rows = sum(r[0] for r in results.values())
        total_resolved = sum(r[1] for r in results.values())
        print(f"\nSummary: Processed {total_files} files, {total_rows} total rows, {total_resolved} values resolved")
    else:
        total, resolved = process_csv(
            args.input,
            args.output,
            args.source_root,
            args.language,
            args.value_column,
            args.location_column
        )
        print(f"Processed {total} rows, resolved {resolved} truncated values")
        print(f"Output written to {args.output}")


if __name__ == "__main__":
    main()
