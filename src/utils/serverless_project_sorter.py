#!/usr/bin/env python3
"""
Helper script to parse serverless.yml files and group projects by provider and language.

Usage:
    python serverless_project_sorter.py <path_to_json_files>

The script:
1. Loads all .json files from the input path (each containing a list of project paths)
2. For each path, finds serverless.yml or serverless.yaml
3. Extracts provider.name and provider.runtime
4. Groups results by provider -> language -> [paths]
5. Outputs sorted_projects.json and failed.json to the input path
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml


# Custom YAML loader to handle CloudFormation intrinsic functions
# These tags are commonly used in serverless.yml files
class CloudFormationLoader(yaml.SafeLoader):
    """Custom YAML loader that handles CloudFormation intrinsic functions."""
    pass


def _construct_cfn_tag(loader, tag_suffix, node):
    """Generic constructor for CloudFormation tags."""
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {tag_suffix: loader.construct_mapping(node)}
    return None


# Register CloudFormation intrinsic function handlers
CFN_TAGS = [
    '!Ref', '!GetAtt', '!Sub', '!Join', '!Select', '!Split',
    '!ImportValue', '!FindInMap', '!GetAZs', '!Cidr',
    '!Base64', '!Condition', '!If', '!Not', '!And', '!Or', '!Equals',
    '!Transform'
]

for tag in CFN_TAGS:
    tag_name = tag[1:]  # Remove the '!' prefix
    CloudFormationLoader.add_constructor(
        tag,
        lambda loader, node, t=tag_name: _construct_cfn_tag(loader, t, node)
    )


# Runtime normalization mappings
# Maps runtime patterns to normalized language names
RUNTIME_PATTERNS = [
    # Node.js variations: nodejs, nodejs4.3, nodejs6.10, nodejs8.10, nodejs10.x, nodejs12.x, etc.
    (r'^nodejs[\d.x]*$', 'nodejs'),
    (r'^node[\d.x]*$', 'nodejs'),

    # Python variations: python2.7, python3.6, python3.7, python3.8, python3.9, python3.10, python3.11, python3.12
    (r'^python[\d.]*$', 'python'),

    # Go variations: go1.x, go1.21, etc.
    (r'^go[\d.x]*$', 'go'),

    # .NET variations: dotnetcore1.0, dotnetcore2.0, dotnetcore2.1, dotnetcore3.1, dotnet6, dotnet7, dotnet8
    (r'^dotnetcore[\d.]*$', 'dotnet'),
    (r'^dotnet[\d.]*$', 'dotnet'),

    # Java variations: java8, java8.al2, java11, java17, java21
    (r'^java[\d.]*(?:\.al2)?$', 'java'),

    # Ruby variations: ruby2.5, ruby2.7, ruby3.2
    (r'^ruby[\d.]*$', 'ruby'),

    # Rust/Custom runtime: provided, provided.al2, provided.al2023
    (r'^provided(?:\.al2(?:023)?)?$', 'provided'),
]


def resolve_serverless_variables(runtime: str) -> str:
    """
    Resolve Serverless Framework variable syntax to extract actual runtime values.

    Handles patterns like:
        ${env:runtime, 'python3.9'} -> python3.9
        nodejs${env:node_version, '20'}.x -> nodejs20.x
        ${opt:runtime, "nodejs14.x"} -> nodejs14.x
        ${self:custom.runtime, 'go1.x'} -> go1.x

    Args:
        runtime: Raw runtime string that may contain variable interpolation

    Returns:
        Resolved runtime string with variables replaced by their defaults
    """
    if not runtime or '${' not in runtime:
        return runtime

    # Pattern to match Serverless variable syntax with default values
    # Matches: ${source:var, 'default'} or ${source:var, "default"}
    # Also handles spaces around the comma and quotes
    var_pattern = r"\$\{[^,}]+,\s*['\"]([^'\"]+)['\"]\s*\}"

    # Replace all variable patterns with their default values
    resolved = re.sub(var_pattern, r'\1', runtime)

    # If we still have unresolved variables (no default), return as-is
    # This handles cases like ${self:custom.runtime} without defaults
    if '${' in resolved:
        # Try to extract just the variable reference for logging purposes
        # but return as unknown since we can't resolve it
        return runtime

    return resolved


def normalize_runtime(runtime: str) -> str:
    """
    Normalize runtime string to a standard language name.

    Examples:
        nodejs14.x -> nodejs
        python3.9 -> python
        go1.x -> go
        dotnetcore2.1 -> dotnet
        ${env:runtime, 'python3.9'} -> python
        nodejs${env:node_version, '20'}.x -> nodejs
        ${self:custom.runtime} -> other (unresolved)
    """
    if not runtime:
        return 'unknown'

    # First resolve any Serverless variable interpolation
    resolved_runtime = resolve_serverless_variables(runtime)

    # If still contains unresolved variables, group as 'other'
    if '$' in resolved_runtime:
        return 'other'

    runtime_lower = resolved_runtime.lower().strip()

    for pattern, normalized in RUNTIME_PATTERNS:
        if re.match(pattern, runtime_lower, re.IGNORECASE):
            return normalized

    # If no pattern matches, return the original (lowercased)
    return runtime_lower


def load_serverless_config(path: str) -> dict[str, Any]:
    """
    Load serverless.yml or serverless.yaml from the given path.

    Args:
        path: Directory path to search for serverless config

    Returns:
        Parsed YAML content as dictionary

    Raises:
        FileNotFoundError: If no serverless config file found
        yaml.YAMLError: If YAML parsing fails
    """
    path = Path(path)

    # Try both .yml and .yaml extensions
    for filename in ['serverless.yml', 'serverless.yaml']:
        config_path = path / filename
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.load(f, Loader=CloudFormationLoader)

    raise FileNotFoundError(f"No serverless.yml or serverless.yaml found in {path}")


def extract_provider_info(config: dict[str, Any]) -> tuple[str, str]:
    """
    Extract provider name and runtime from serverless config.

    Args:
        config: Parsed serverless.yml content

    Returns:
        Tuple of (provider_name, normalized_runtime)

    Raises:
        KeyError: If required fields are missing
    """
    provider = config.get('provider', {})

    if not provider:
        raise KeyError("Missing 'provider' section in serverless config")

    # Get provider name
    provider_name = provider.get('name')
    if not provider_name:
        raise KeyError("Missing 'provider.name' in serverless config")

    # Get runtime - can be at provider level or function level
    # First check provider level
    runtime = provider.get('runtime')

    # If no provider-level runtime, check functions for runtime
    if not runtime:
        functions = config.get('functions', {})
        for func_config in functions.values():
            if isinstance(func_config, dict) and 'runtime' in func_config:
                runtime = func_config['runtime']
                break

    if not runtime:
        raise KeyError("Missing 'provider.runtime' in serverless config (neither at provider nor function level)")

    normalized_runtime = normalize_runtime(runtime)

    # Normalize provider name - if it contains unresolved variables, group as 'other'
    resolved_provider = resolve_serverless_variables(str(provider_name))
    if '$' in resolved_provider:
        resolved_provider = 'other'
    else:
        resolved_provider = resolved_provider.lower()

    return resolved_provider, normalized_runtime


def load_paths_from_json_files(input_path: str) -> list[str]:
    """
    Load all paths from .json files in the input directory.

    Args:
        input_path: Directory containing .json files with path lists

    Returns:
        Combined list of all paths from all JSON files
    """
    input_path = Path(input_path)
    all_paths = []

    for json_file in input_path.glob('*.json'):
        # Skip our output files
        if json_file.name in ['sorted_projects.json', 'failed.json']:
            continue

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_paths.extend(data)
                else:
                    print(f"Warning: {json_file} does not contain a list, skipping")
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: Failed to load {json_file}: {e}")

    return all_paths


def process_projects(input_path: str) -> tuple[dict[str, dict[str, list[str]]], dict[str, str]]:
    """
    Process all projects and group them by provider and language.

    Args:
        input_path: Path containing JSON files with project paths

    Returns:
        Tuple of (sorted_projects, failed_projects)
        - sorted_projects: {provider: {language: [paths]}}
        - failed_projects: {path: error_message}
    """
    sorted_projects: dict[str, dict[str, list[str]]] = {}
    failed_projects: dict[str, str] = {}

    paths = load_paths_from_json_files(input_path)

    for project_path in paths:
        try:
            config = load_serverless_config(project_path)
            provider_name, runtime = extract_provider_info(config)

            # Initialize nested structure if needed
            if provider_name not in sorted_projects:
                sorted_projects[provider_name] = {}
            if runtime not in sorted_projects[provider_name]:
                sorted_projects[provider_name][runtime] = []

            sorted_projects[provider_name][runtime].append(project_path)

        except Exception as e:
            failed_projects[project_path] = str(e)

    return sorted_projects, failed_projects


def print_statistics(sorted_projects: dict[str, dict[str, list[str]]],
                     failed_projects: dict[str, str]) -> None:
    """
    Print statistics about the processed projects.
    """
    print("\n" + "=" * 60)
    print("SERVERLESS PROJECT STATISTICS")
    print("=" * 60)

    # List of providers and their totals
    print("\nProviders Found:")
    print("-" * 40)

    total_projects = 0
    for provider, languages in sorted(sorted_projects.items()):
        provider_total = sum(len(paths) for paths in languages.values())
        total_projects += provider_total
        print(f"  {provider}: {provider_total} projects")

    print(f"\nTotal successful projects: {total_projects}")

    # AWS language distribution (if AWS exists)
    if 'aws' in sorted_projects:
        print("\n" + "-" * 40)
        print("AWS Provider - Language Distribution:")
        print("-" * 40)

        aws_languages = sorted_projects['aws']
        for language, paths in sorted(aws_languages.items(), key=lambda x: -len(x[1])):
            print(f"  {language}: {len(paths)} projects")

    # Failed projects
    print("\n" + "-" * 40)
    print(f"Failed to parse: {len(failed_projects)} projects")
    print("-" * 40)

    # if failed_projects:
    #     for path, error in list(failed_projects.items())[:10]:  # Show first 10
    #         print(f"  {path}")
    #         print(f"    Error: {error}")
    #     if len(failed_projects) > 10:
    #         print(f"  ... and {len(failed_projects) - 10} more")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Parse serverless.yml files and group projects by provider and language.'
    )
    parser.add_argument(
        'input_path',
        help='Path containing .json files with lists of project paths'
    )

    args = parser.parse_args()
    input_path = Path(args.input_path)

    if not input_path.exists():
        print(f"Error: Input path does not exist: {input_path}")
        sys.exit(1)

    if not input_path.is_dir():
        print(f"Error: Input path is not a directory: {input_path}")
        sys.exit(1)

    # Process projects
    print(f"Processing projects from: {input_path}")
    sorted_projects, failed_projects = process_projects(str(input_path))

    # Save sorted projects
    output_file = input_path / 'sorted_projects.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sorted_projects, f, indent=2)
    print(f"Saved sorted projects to: {output_file}")

    # Save failed projects
    failed_file = input_path / 'failed.json'
    with open(failed_file, 'w', encoding='utf-8') as f:
        json.dump(failed_projects, f, indent=2)
    print(f"Saved failed projects to: {failed_file}")

    # Print statistics
    print_statistics(sorted_projects, failed_projects)


if __name__ == '__main__':
    main()
