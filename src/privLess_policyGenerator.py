#!/usr/bin/env python3
"""
IAM Policy Generator for PrivLess.

Generates minimal IAM policies from analysis results, with comprehensive
statistics collection.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Any, Tuple

import yaml

from utils.log import setup_logger


class PolicyGenerator:
    """Generates least-privilege IAM policies from CodeQL analysis results."""

    ARN_PATTERNS = {
        's3': {
            'Bucket': 'arn:aws:s3:::{bucket}/*',
            'Key': 'arn:aws:s3:::{bucket}/{key}',
        },
        'dynamodb': {
            'TableName': 'arn:aws:dynamodb:{region}:{account}:table/{table_name}',
        },
        'sqs': {
            'QueueUrl': 'arn:aws:sqs:{region}:{account}:{queue_name}',
            'QueueName': 'arn:aws:sqs:{region}:{account}:{queue_name}',
        },
        'sns': {
            'TopicArn': '{topic_arn}',
            'TargetArn': '{target_arn}',
        },
        'lambda': {
            'FunctionName': 'arn:aws:lambda:{region}:{account}:function:{function_name}',
        },
        'kinesis': {
            'StreamName': 'arn:aws:kinesis:{region}:{account}:stream/{stream_name}',
        },
        'cloudwatch': {
            'Namespace': '*',
        },
    }

    RESOURCE_NAMES = {
        's3': ['Bucket', 'Key'],
        'dynamodb': ['TableName'],
        'sqs': ['QueueUrl', 'QueueName'],
        'sns': ['TopicArn', 'TargetArn'],
        'lambda': ['FunctionName'],
        'kinesis': ['StreamName', 'StreamARN'],
        'cloudwatch': ['Namespace'],
    }

    def __init__(
        self,
        permission_map_path: str = 'iam_service_actions.json',
        stats_output_path: str = None,
        empty_apps_path: str = None,
        cfg: Dict[str, Any] = None,
    ):
        self.permission_map_path = permission_map_path
        self.permission_map = {}
        self.stats_output_path = stats_output_path
        self.empty_apps_path = empty_apps_path
        self.current_stats = {}
        self.is_empty_app = False
        self.cfg = cfg or {}
        self.log = setup_logger("policy_generator", self.cfg)

    def load_permission_map(self) -> bool:
        """Load the IAM permission mapping from JSON file."""
        try:
            with open(self.permission_map_path, 'r') as f:
                raw_map = json.load(f)

            self.permission_map = {}
            for service, methods in raw_map.items():
                service_lower = service.lower()
                self.permission_map[service_lower] = {}
                for method, actions in methods.items():
                    method_normalized = self._normalize_method_name(method)
                    self.permission_map[service_lower][method_normalized] = actions

            self.log.info("Loaded permission map with %d services.", len(self.permission_map))
            return True
        except FileNotFoundError:
            self.log.error("Permission map not found: %s", self.permission_map_path)
            return False
        except json.JSONDecodeError as e:
            self.log.error("Invalid JSON in permission map: %s", e)
            return False

    @staticmethod
    def _normalize_method_name(method_name: str) -> str:
        normalized = method_name.replace('_', '').lower()
        if normalized.endswith('withcontext'):
            normalized = normalized[:-11]
        return normalized

    def get_permission(self, service: str, method: str) -> List[str]:
        """Map a service method to its IAM permissions."""
        service_lower = service.lower()
        method_normalized = self._normalize_method_name(method)

        if service_lower in self.permission_map:
            service_map = self.permission_map[service_lower]
            if method_normalized in service_map:
                return service_map[method_normalized]

        method_parts = re.split(r'[_\s]+', method)
        pascal_case = ''.join(word.capitalize() for word in method_parts)
        fallback_action = f"{service_lower}:{pascal_case}"
        self.log.warning("No mapping for %s.%s, using fallback: %s", service, method, fallback_action)
        return [fallback_action]

    def _extract_resource_values(self, resource_data: Dict) -> Set[str]:
        values = set()
        if 'values' not in resource_data:
            return values
        for item in resource_data['values']:
            if isinstance(item, str):
                value = item
            elif isinstance(item, dict) and 'value' in item:
                value = item['value']
            else:
                continue
            if ':' in value:
                value = value.split(':')[-1]
            values.add(value)
        return values

    def _build_arn(self, service: str, resource_type: str, resource_values: Set[str],
                   region: str = '*', account: str = '*') -> List[str]:
        service_lower = service.lower()

        if service_lower not in self.ARN_PATTERNS:
            return [f"arn:aws:{service_lower}:{region}:{account}:{v}" for v in resource_values]

        service_patterns = self.ARN_PATTERNS[service_lower]
        if resource_type not in service_patterns:
            return [f"arn:aws:{service_lower}:{region}:{account}:{v}" for v in resource_values]

        pattern = service_patterns[resource_type]
        arns = []
        for value in resource_values:
            if '{bucket}' in pattern and '{key}' in pattern:
                arn = pattern.format(bucket=value, key='*')
            elif pattern.startswith('{') and pattern.endswith('}'):
                arn = value
            else:
                arn = pattern.format(
                    bucket=value, key=value, table_name=value, queue_name=value,
                    topic_arn=value, target_arn=value, function_name=value,
                    stream_name=value, region=region, account=account,
                )
            arns.append(arn)
        return arns if arns else ['*']

    def _compile_service_data(self, analysis_results: List[Dict]) -> Dict[str, List[Dict]]:
        service_data = defaultdict(list)
        for entry in analysis_results:
            service = entry.get('service', '').lower()
            if service:
                service_data[service].append(entry)
        return dict(service_data)

    def _group_by_actions_and_resources(self, entries: List[Dict], service: str) -> List[Dict]:
        action_to_resources = defaultdict(set)
        relevant_resources = self.RESOURCE_NAMES.get(service.lower(), [])

        if service.lower() == 's3':
            return self._group_s3_resources(entries)

        for entry in entries:
            method = entry.get('serviceAction', '')
            actions = self.get_permission(service, method)
            action_key = frozenset(actions)
            resources_data = entry.get('resources', {})

            for resource_type, resource_info in resources_data.items():
                if relevant_resources and resource_type not in relevant_resources:
                    continue
                values = self._extract_resource_values(resource_info)
                arns = self._build_arn(service, resource_type, values)
                action_to_resources[action_key].update(arns)

        statements = []
        for actions, resources in action_to_resources.items():
            statements.append({
                'actions': sorted(list(actions)),
                'resources': sorted(list(resources)),
            })
        return statements

    def _group_s3_resources(self, entries: List[Dict]) -> List[Dict]:
        action_to_s3_resources = defaultdict(lambda: {'buckets': set(), 'keys': set()})

        for entry in entries:
            method = entry.get('serviceAction', '')
            actions = self.get_permission('s3', method)
            action_key = frozenset(actions)
            resources_data = entry.get('resources', {})

            if 'Bucket' in resources_data:
                action_to_s3_resources[action_key]['buckets'].update(
                    self._extract_resource_values(resources_data['Bucket']))
            if 'Key' in resources_data:
                action_to_s3_resources[action_key]['keys'].update(
                    self._extract_resource_values(resources_data['Key']))

        statements = []
        for actions, resources in action_to_s3_resources.items():
            buckets = resources['buckets']
            keys = resources['keys']
            combined_arns = set()
            actions_list = list(actions)
            is_bucket_operation = any(
                'ListBucket' in a or 'GetBucketLocation' in a or
                'CreateBucket' in a or 'DeleteBucket' in a
                for a in actions_list
            )

            if buckets and keys:
                for bucket in buckets:
                    if is_bucket_operation:
                        combined_arns.add(f"arn:aws:s3:::{bucket}")
                    for key in keys:
                        has_wildcard = key.endswith('/*') or key.endswith('*')
                        key_clean = key.rstrip('/*').rstrip('*').strip('/')
                        if not key_clean:
                            continue
                        if has_wildcard:
                            combined_arns.add(f"arn:aws:s3:::{bucket}/{key_clean}/*")
                        else:
                            combined_arns.add(f"arn:aws:s3:::{bucket}/{key_clean}")
            elif buckets:
                for bucket in buckets:
                    combined_arns.add(f"arn:aws:s3:::{bucket}")
                    if not is_bucket_operation:
                        combined_arns.add(f"arn:aws:s3:::{bucket}/*")
            elif keys:
                for key in keys:
                    if '/' in key:
                        combined_arns.add(f"arn:aws:s3:::{key}")
                    else:
                        combined_arns.add(f"arn:aws:s3:::*/{key}")

            if combined_arns:
                statements.append({
                    'actions': sorted(actions_list),
                    'resources': sorted(list(combined_arns)),
                })
        return statements

    def _extract_function_path(self, path: str) -> str:
        if ':' in path:
            path = path.rsplit(':')[0]
        if '@' in path:
            path = path.split('@')[0]
        return path

    def _group_by_function(self, analysis_results: List[Dict]) -> Dict[str, List[Dict]]:
        function_data = defaultdict(list)
        for entry in analysis_results:
            path = entry.get('path', '')
            if path:
                function_path = self._extract_function_path(path)
                function_data[function_path].append(entry)
        return dict(function_data)

    def _is_wildcard_resource(self, resource: str) -> bool:
        return '*' in resource or resource == 'UNKNOWN'

    def _collect_service_stats(self, analysis_results: List[Dict]) -> Dict[str, Any]:
        service_stats = defaultdict(lambda: {
            'call_count': 0, 'unique_actions': set(), 'resource_count': 0,
            'wildcard_resources': 0, 'specific_resources': 0, 'unresolved_resources': 0,
        })
        for entry in analysis_results:
            service = entry.get('service', '').lower()
            action = entry.get('serviceAction', '')
            if not service:
                continue
            service_stats[service]['call_count'] += 1
            service_stats[service]['unique_actions'].add(action)
            for resource_name, resource_info in entry.get('resources', {}).items():
                values = self._extract_resource_values(resource_info)
                service_stats[service]['resource_count'] += len(values)
                for value in values:
                    if value.startswith('UNRESOLVED:'):
                        service_stats[service]['unresolved_resources'] += 1
                    elif self._is_wildcard_resource(value):
                        service_stats[service]['wildcard_resources'] += 1
                    else:
                        service_stats[service]['specific_resources'] += 1

        result = {}
        for service, stats in service_stats.items():
            result[service] = {
                'call_count': stats['call_count'],
                'unique_actions': sorted(list(stats['unique_actions'])),
                'action_count': len(stats['unique_actions']),
                'resource_count': stats['resource_count'],
                'wildcard_resources': stats['wildcard_resources'],
                'specific_resources': stats['specific_resources'],
                'unresolved_resources': stats['unresolved_resources'],
            }
        return result

    def _collect_function_stats(self, analysis_results: List[Dict], policies: Dict) -> Dict[str, Any]:
        function_data = self._group_by_function(analysis_results)
        function_stats = {}
        for function_path, entries in function_data.items():
            services = set()
            for entry in entries:
                services.add(entry.get('service', '').lower())
            policy = policies.get(function_path, {})
            statements = policy.get('Statement', [])
            permission_count = sum(len(stmt.get('Action', [])) for stmt in statements)
            total_resources = sum(len(stmt.get('Resource', [])) for stmt in statements)
            wildcard_resources = sum(
                1 for stmt in statements for r in stmt.get('Resource', []) if self._is_wildcard_resource(r)
            )
            function_stats[function_path] = {
                'service_call_count': len(entries),
                'unique_services': sorted(list(services)),
                'service_count': len(services),
                'permission_count': permission_count,
                'resource_count': total_resources,
                'wildcard_resources': wildcard_resources,
                'specific_resources': total_resources - wildcard_resources,
                'statement_count': len(statements),
            }
        return function_stats

    def _collect_permission_stats(self, policies: Dict, per_function: bool) -> Dict[str, Any]:
        permission_counts = defaultdict(int)
        if per_function and not policies.get('Version'):
            for function_path, policy in policies.items():
                for stmt in policy.get('Statement', []):
                    for action in stmt.get('Action', []):
                        permission_counts[action] += 1
        else:
            for stmt in policies.get('Statement', []):
                for action in stmt.get('Action', []):
                    permission_counts[action] += 1

        sorted_permissions = sorted(permission_counts.items(), key=lambda x: x[1], reverse=True)
        return {
            'total_unique_permissions': len(permission_counts),
            'permission_frequency': dict(sorted_permissions[:20]),
            'permission_distribution': dict(sorted_permissions),
        }

    def _collect_dangerous_permission_stats(self, policies: Dict, per_function: bool) -> Dict[str, Any]:
        dangerous_found = {}
        if per_function and not policies.get('Version'):
            for function_path, policy in policies.items():
                for stmt in policy.get('Statement', []):
                    for action in stmt.get('Action', []):
                        if 'delete' in action.lower() or 'update' in action.lower():
                            if action not in dangerous_found:
                                dangerous_found[action] = {'functions': [], 'count': 0}
                            dangerous_found[action]['functions'].append(function_path)
                            dangerous_found[action]['count'] += 1
        else:
            for stmt in policies.get('Statement', []):
                for action in stmt.get('Action', []):
                    if 'delete' in action.lower() or 'update' in action.lower():
                        if action not in dangerous_found:
                            dangerous_found[action] = {'count': 1}
                        else:
                            dangerous_found[action]['count'] += 1
        return dangerous_found

    def _calculate_application_stats(self, app_name, app_path, analysis_results, policies, per_function):
        function_data = self._group_by_function(analysis_results)
        services = set()
        total_resources = 0
        resolved_resources = 0
        unresolved_resources = 0

        for entry in analysis_results:
            services.add(entry.get('service', '').lower())
            for resource_name, resource_info in entry.get('resources', {}).items():
                total_resources += 1
                if resource_info.get('confidence') == 'RESOLVED':
                    resolved_resources += 1
                else:
                    unresolved_resources += 1

        if per_function and not policies.get('Version'):
            total_statements = sum(len(p.get('Statement', [])) for p in policies.values())
            total_permissions = sum(
                sum(len(stmt.get('Action', [])) for stmt in p.get('Statement', []))
                for p in policies.values()
            )
        else:
            total_statements = len(policies.get('Statement', []))
            total_permissions = sum(len(stmt.get('Action', [])) for stmt in policies.get('Statement', []))

        return {
            'app_name': app_name,
            'app_path': app_path,
            'timestamp': datetime.now().isoformat(),
            'analysis_metrics': {
                'total_functions': len(function_data),
                'total_service_calls': len(analysis_results),
                'unique_services': sorted(list(services)),
                'service_count': len(services),
                'total_resources': total_resources,
                'resolved_resources': resolved_resources,
                'unresolved_resources': unresolved_resources,
                'resolution_rate': round(resolved_resources / total_resources, 3) if total_resources > 0 else 0,
                'total_statements': total_statements,
                'total_permissions': total_permissions,
            },
            'service_usage': self._collect_service_stats(analysis_results),
            'function_metrics': self._collect_function_stats(analysis_results, policies) if per_function else {},
            'permission_stats': self._collect_permission_stats(policies, per_function),
            'dangerous_permissions': self._collect_dangerous_permission_stats(policies, per_function),
        }

    def generate_policy(self, app, analysis_results, region='*', account='*',
                        per_function=True, collect_stats=True, app_path=None):
        """Generate IAM policy/policies from analysis results."""
        if not self.permission_map:
            self.log.error("Permission map not loaded. Call load_permission_map() first.")
            return {}

        if per_function:
            function_data = self._group_by_function(analysis_results)
            policies = {}
            for function_path, entries in function_data.items():
                app_name = function_path.split('/')[-1].split('.')[0]
                policy = self._generate_single_policy(entries, region, account)
                policies[app_name] = policy
        else:
            policies = self._generate_single_policy(analysis_results, region, account)

        if collect_stats:
            self.current_stats = self._calculate_application_stats(
                app, app_path or '', analysis_results, policies, per_function)

        self.is_empty_app = self._check_if_empty_app(policies, per_function)
        return policies

    def _check_if_empty_app(self, policies, per_function):
        if not policies:
            return True
        if per_function and not policies.get('Version'):
            for function_path, policy in policies.items():
                if policy.get('Statement', []):
                    return False
            return True
        else:
            return len(policies.get('Statement', [])) == 0

    def _generate_single_policy(self, analysis_results, region='*', account='*'):
        service_data = self._compile_service_data(analysis_results)
        all_statements = []
        for service, entries in service_data.items():
            statements = self._group_by_actions_and_resources(entries, service)
            all_statements.extend(statements)
        optimized_statements = self._optimize_statements(all_statements)
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": stmt['actions'], "Resource": stmt['resources']}
                for stmt in optimized_statements
            ],
        }

    def _optimize_statements(self, statements):
        resource_to_actions = defaultdict(set)
        for stmt in statements:
            resource_key = frozenset(stmt['resources'])
            resource_to_actions[resource_key].update(stmt['actions'])
        optimized = []
        for resources, actions in resource_to_actions.items():
            optimized.append({
                'actions': sorted(list(actions)),
                'resources': sorted(list(resources)),
            })
        return optimized

    def _policy_to_iam_role_statements(self, policy):
        statements = []
        for stmt in policy.get('Statement', []):
            iam_stmt = {'Effect': stmt.get('Effect', 'Allow')}
            iam_stmt['Action'] = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            iam_stmt['Resource'] = resources[0] if len(resources) == 1 else resources
            statements.append(iam_stmt)
        return statements

    def generate_policy_json(self, app, analysis_results, output_file=None,
                             region='*', account='*', per_function=True,
                             indent=2, collect_stats=True, app_path=None):
        policies = self.generate_policy(app, analysis_results, region, account,
                                        per_function, collect_stats, app_path)
        policy_json = json.dumps(policies, indent=indent)
        if output_file:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(policy_json)
            self.log.info("Policy (JSON) written to %s", output_file)
        return policy_json

    def generate_policy_yaml(self, app, analysis_results, output_file=None,
                             region='*', account='*', per_function=True,
                             collect_stats=True, app_path=None):
        policies = self.generate_policy(app, analysis_results, region, account,
                                        per_function, collect_stats, app_path)

        if per_function and not policies.get('Version'):
            yaml_output = {}
            for function_name, policy in policies.items():
                iam_statements = self._policy_to_iam_role_statements(policy)
                yaml_output[function_name] = {'iamRoleStatements': iam_statements}
        else:
            iam_statements = self._policy_to_iam_role_statements(policies)
            yaml_output = {'iamRoleStatements': iam_statements}

        yaml_string = yaml.dump(yaml_output, default_flow_style=False,
                                sort_keys=False, allow_unicode=True, indent=2)
        if output_file:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(yaml_string)
            self.log.info("Policy (YAML) written to %s", output_file)
        return yaml_string

    def generate_policy_file(self, app, analysis_results, output_file=None,
                             region='*', account='*', per_function=True,
                             output_format='json', collect_stats=True, app_path=None):
        """Generate policy and save in specified format."""
        if output_file:
            ext = os.path.splitext(output_file)[1].lower()
            if ext in ('.yml', '.yaml'):
                output_format = 'yaml'
            elif ext == '.json':
                output_format = 'json'

        if output_format.lower() == 'yaml':
            return self.generate_policy_yaml(
                app, analysis_results, output_file, region, account,
                per_function, collect_stats, app_path)
        else:
            return self.generate_policy_json(
                app, analysis_results, output_file, region, account,
                per_function, indent=2, collect_stats=collect_stats, app_path=app_path)

    def get_current_stats(self):
        return self.current_stats

    def save_stats(self, stats_file=None, append=True, empty_apps_file=None):
        """Save current application statistics to a JSONL file."""
        if not self.current_stats:
            self.log.warning("No statistics to save.")
            return

        if self.is_empty_app:
            self._save_empty_app(empty_apps_file)
            return

        output_file = stats_file or self.stats_output_path
        if not output_file:
            self.log.error("No stats output file specified.")
            return

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        mode = 'a' if append else 'w'
        try:
            with open(output_file, mode) as f:
                json.dump(self.current_stats, f)
                f.write('\n')
            self.log.info("Statistics saved to %s", output_file)
        except Exception as e:
            self.log.error("Error saving statistics: %s", e)

    def _save_empty_app(self, empty_apps_file=None):
        output_file = empty_apps_file or self.empty_apps_path
        if not output_file:
            if self.stats_output_path:
                output_file = os.path.join(os.path.dirname(self.stats_output_path), "empty_apps.json")
            else:
                output_file = "empty_apps.json"

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        empty_app_record = {
            'app_name': self.current_stats.get('app_name', 'Unknown'),
            'app_path': self.current_stats.get('app_path', ''),
            'timestamp': self.current_stats.get('timestamp', datetime.now().isoformat()),
            'reason': 'no_functions_or_policy',
        }

        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    empty_apps = json.load(f)
            else:
                empty_apps = []
            empty_apps.append(empty_app_record)
            with open(output_file, 'w') as f:
                json.dump(empty_apps, f, indent=2)
            self.log.info("Empty app recorded in %s", output_file)
        except Exception as e:
            self.log.error("Error saving empty app record: %s", e)

    @staticmethod
    def load_all_stats(stats_file):
        """Load all application statistics from a JSONL file."""
        if not os.path.exists(stats_file):
            return []
        stats_list = []
        with open(stats_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    stats_list.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return stats_list
