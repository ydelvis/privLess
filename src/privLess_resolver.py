"""
Resource Value Resolver for PrivLess.

Merges service extraction and dataflow analysis results to resolve
resource values in AWS service calls.
"""

import csv
import os
import re
import subprocess
import time
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple

import yaml

from utils.log import setup_logger


class ResourceResolver:
    """
    Resolves resource values by merging service extraction and dataflow analysis results.

    Handles:
    - Fuzzy matching of line numbers for multi-line declarations
    - Resolution of environment variables from serverless config
    - Collection of multiple possible values
    - Confidence level assignment
    """

    RESOURCE_NAMES = [
        "Bucket", "Key",
        "FunctionName",
        "QueueName", "QueueUrl",
        "TopicName", "TopicArn", "TargetArn", "SubscriptionArn",
        "TableName",
        "StateMachineName", "StateMachineArn",
        "DomainName",
        "StreamName", "StreamArn",
        "ClusterName", "Cluster", "ClusterResourceId",
        "DBInstanceIdentifier", "DBClusterIdentifier",
        "AccessPointId",
        "LogGroupName", "MetricName", "Namespace",
        "AppId", "ApplicationId",
        "ThingName", "ThingGroupName", "StreamId",
        "ApiId",
    ]

    def __init__(
        self,
        codeql,
        output_path: str = None,
        line_tolerance: int = 3,
        cfg: Dict[str, Any] = None,
    ):
        """
        Initialize the resolver.

        Args:
            codeql: CodeQL agent instance.
            output_path: Optional default output path for results.
            line_tolerance: Line number tolerance for fuzzy matching (default: 3).
            cfg: Loaded configuration dictionary.
        """
        self.codeql = codeql
        self.line_tolerance = line_tolerance
        self.output_path = output_path
        self.cfg = cfg or {}
        self.log = setup_logger("resolver", self.cfg)

        self.query_type = "resolver"
        self.service_calls: Dict[Tuple, Dict[str, str]] = {}
        self.resolved_values: Dict[Tuple, List[Dict[str, str]]] = {}
        self.serverless_config: Dict[str, Any] = {}
        self.results: List[Dict[str, Any]] = []

    def load_data(self, service_calls, resolved_values, serverless_config_path) -> 'ResourceResolver':
        """Load all input data files."""
        self.log.info("Loading CSV files...")
        self.service_calls = self._parse_service_calls(service_calls)
        self.resolved_values = self._parse_resources(resolved_values)

        self.log.info("Found %d unique service calls, %d resolved value entries.",
                      len(self.service_calls), len(self.resolved_values))

        self.log.info("Loading serverless config from %s", serverless_config_path)
        self.serverless_config = self._load_serverless_config(serverless_config_path)
        return self

    def resolve(self) -> 'ResourceResolver':
        """Resolve resource values by merging the data sources."""
        self.log.info("Resolving resource values (line tolerance: %d)...", self.line_tolerance)
        self.results = self._resolve_resource_values()
        self.log.info("Resolved %d service calls.", len(self.results))
        return self

    def save(self, output_path: Optional[str] = None) -> 'ResourceResolver':
        """Save results to CSV file."""
        path = output_path or self.output_path
        self.log.info("Writing results to %s", path)
        self._write_output(path)
        return self

    def get_results(self) -> List[Dict[str, Any]]:
        """Get the resolved results."""
        return self.results

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics about the resolution."""
        if not self.results:
            return {}

        total_calls = len(self.results)
        total_resources = sum(len(r['resources']) for r in self.results)
        resolved_count = 0
        unresolved_count = 0

        for result in self.results:
            for resource_name, resolution in result['resources'].items():
                if resolution['confidence'] == 'RESOLVED':
                    resolved_count += 1
                else:
                    unresolved_count += 1

        return {
            'total_service_calls': total_calls,
            'total_resources': total_resources,
            'resolved_resources': resolved_count,
            'unresolved_resources': unresolved_count,
            'resolution_rate': f"{(resolved_count / total_resources * 100):.1f}%" if total_resources > 0 else "0%",
        }

    def resolve_resources(self, service_calls, resources, serverless_yml, show_summary: bool = False) -> 'ResourceResolver':
        """
        Convenience method to run the complete pipeline.

        Args:
            service_calls: Path to service extraction CSV.
            resources: Path to resource resolution CSV.
            serverless_yml: Path to serverless.yml.
            show_summary: Whether to log summary (default: False).
        """
        self.load_data(service_calls, resources, serverless_yml).resolve()
        if show_summary:
            stats = self.get_summary_stats()
            self.log.info("Resolution stats: %s", stats)
        return self

    def run_data_flow_analysis(self, project_name, project_db_path):
        """Run the data-flow resolution query via CodeQL."""
        start = time.perf_counter()
        try:
            output = self.codeql.run_query(
                query_type=self.query_type,
                project_name=project_name,
                project_db_path=project_db_path,
            )

            if output and os.path.exists(output):
                elapsed = time.perf_counter() - start
                self.log.info("Resource values extracted for %s -> %s", project_name, output)
                return (output, elapsed)
            else:
                self.log.warning("Resource extraction produced no output for %s.", project_name)
                return (None, None)

        except subprocess.CalledProcessError as e:
            self.log.error("CodeQL query error for %s: %s", project_db_path, e)
            return (None, None)
        except Exception as e:
            self.log.error("Unexpected error during resource extraction: %s", e)
            return (None, None)

    # -- Private helpers --

    def _parse_service_calls(self, service_calls_path) -> Dict[Tuple, Dict[str, str]]:
        service_calls = defaultdict(dict)
        with open(service_calls_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row['path'], row['service'], row['serviceAction'])
                service_calls[key][row['resourceName']] = row['resourceValue']
        return dict(service_calls)

    def _parse_resources(self, resources_path) -> Dict[Tuple, List[Dict[str, str]]]:
        resolved_values = defaultdict(list)
        with open(resources_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row['path'], row['serviceAction'], row['resourceName'])
                resolved_values[key].append({
                    'resourceValue': row['resourceValue'],
                    'valueSource': row['valueSource'],
                })
        return dict(resolved_values)

    def _load_serverless_config(self, serverless_config_path) -> Dict[str, Any]:
        try:
            with open(serverless_config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            self.log.warning("Serverless config not found: %s", serverless_config_path)
            return {}
        except Exception as e:
            self.log.warning("Error loading serverless config: %s", e)
            return {}

    @staticmethod
    def _extract_line_number(path: str) -> Tuple[str, Optional[int]]:
        parts = path.rsplit(':', 1)
        if len(parts) == 2:
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return path, None
        return path, None

    @staticmethod
    def _fuzzy_match_path(path1: str, path2: str, tolerance: int = 3) -> bool:
        file1, line1 = ResourceResolver._extract_line_number(path1)
        file2, line2 = ResourceResolver._extract_line_number(path2)
        if file1 != file2:
            return False
        if line1 is None or line2 is None:
            return True
        return abs(line1 - line2) <= tolerance

    @staticmethod
    def _format_env_value(value: Any) -> str:
        if isinstance(value, dict):
            if 'Ref' in value:
                return f"{{Ref: {value['Ref']}}}"
            elif 'Fn::GetAtt' in value:
                return f"{{Fn::GetAtt: {value['Fn::GetAtt']}}}"
            elif 'Fn::Sub' in value:
                return f"{{Fn::Sub: {value['Fn::Sub']}}}"
            elif 'Fn::Join' in value:
                return f"{{Fn::Join: {value['Fn::Join']}}}"
            else:
                return str(value)
        elif isinstance(value, str):
            return value
        else:
            return str(value)

    def _resolve_env_var(self, var_name: str) -> str:
        if 'provider' in self.serverless_config:
            provider_env = self.serverless_config['provider'].get('environment', {})
            if var_name in provider_env:
                return self._format_env_value(provider_env[var_name])

        if 'functions' in self.serverless_config:
            for func_name, func_config in self.serverless_config['functions'].items():
                if isinstance(func_config, dict) and 'environment' in func_config:
                    func_env = func_config['environment']
                    if var_name in func_env:
                        return self._format_env_value(func_env[var_name])

        if 'custom' in self.serverless_config:
            custom = self.serverless_config['custom']
            if var_name in custom:
                return self._format_env_value(custom[var_name])
            var_name_lower = var_name.lower()
            for key, value in custom.items():
                if key.lower() == var_name_lower:
                    return self._format_env_value(value)

        return f"ENV:{var_name}"

    def _resolve_self_reference(self, ref: str) -> str:
        if not ref.startswith('${self:') or not ref.endswith('}'):
            return ref
        path = ref[7:-1]
        parts = path.split('.')
        current = self.serverless_config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return ref
        return self._format_env_value(current)

    def _resolve_resource_values(self) -> List[Dict[str, Any]]:
        results = []
        for (path, service, service_action), resources in self.service_calls.items():
            call_info = {
                'path': path,
                'service': service,
                'serviceAction': service_action,
                'resources': {},
            }

            for resource_name, resource_variable in resources.items():
                matches = []
                for (res_path, res_action, resource), resolutions in self.resolved_values.items():
                    if res_action == service_action and resource == resource_name:
                        if self._fuzzy_match_path(path, res_path, self.line_tolerance):
                            matches.extend(resolutions)

                if not matches:
                    call_info['resources'][resource_name] = {
                        'values': [f'UNRESOLVED:{resource_variable}'],
                        'confidence': 'NONE',
                    }
                else:
                    value_sources = [m['valueSource'] for m in matches]
                    if all(vs == 'PARAMETER' for vs in value_sources):
                        call_info['resources'][resource_name] = {
                            'values': [f'UNRESOLVED:{resource_variable}'],
                            'confidence': 'NONE',
                        }
                    else:
                        resolved_list = []
                        for match in matches:
                            if match['valueSource'] != 'PARAMETER':
                                value = match['resourceValue']
                                source = match['valueSource']
                                if source == 'ENV_VAR':
                                    resolved_value = self._resolve_env_var(value)
                                    if '${self:' in resolved_value:
                                        resolved_value = self._resolve_self_reference(resolved_value)
                                    value = resolved_value
                                resolved_list.append({'value': value, 'source': source})

                        seen = set()
                        unique_resolved = []
                        for item in resolved_list:
                            item_tuple = (item['value'], item['source'])
                            if item_tuple not in seen:
                                seen.add(item_tuple)
                                unique_resolved.append(item)

                        call_info['resources'][resource_name] = {
                            'values': unique_resolved if unique_resolved else [f'UNRESOLVED:{resource_variable}'],
                            'confidence': 'RESOLVED' if unique_resolved else 'NONE',
                        }

            results.append(call_info)
        return results

    def _write_output(self, output_path: str):
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['path', 'service', 'serviceAction', 'resourceName',
                             'resolvedValues', 'valueSources', 'confidence'])
            for call in self.results:
                for resource_name, resolution in call['resources'].items():
                    values = resolution['values']
                    if isinstance(values, list) and len(values) > 0:
                        if isinstance(values[0], dict):
                            value_str = '|'.join([v['value'] for v in values])
                            source_str = '|'.join([v['source'] for v in values])
                        else:
                            value_str = values[0]
                            source_str = 'UNRESOLVED'
                    else:
                        value_str = 'UNKNOWN'
                        source_str = 'UNKNOWN'
                    writer.writerow([
                        call['path'], call['service'], call['serviceAction'],
                        resource_name, value_str, source_str, resolution['confidence'],
                    ])
