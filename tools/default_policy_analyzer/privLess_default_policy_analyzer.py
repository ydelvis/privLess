#!/usr/bin/env python3
"""
Default Policy Analyzer for Serverless Framework Applications

This module analyzes serverless.yml/yaml files to extract IAM policy configurations
and generate statistics comparable to the dynamic analysis output from privLess.

It handles various IAM statement formats:
- provider.iamRoleStatements (legacy)
- provider.iam.role.statements (Serverless Framework v3+)
- function-level iamRoleStatements (requires serverless-iam-roles-per-function plugin)
- function-level iamRoleStatementsInherit

Author: PrivLess Team
"""

import json
import os
import re
import argparse
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

# Optional tqdm support for progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Project root: tools/default_policy_analyzer/ -> tools/ -> project_root/
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))


def _get_results_dir() -> str:
    """Resolve the results output directory from config.yaml."""
    config_path = os.path.join(_PROJECT_ROOT, "config.yaml")
    output_dir = "output"
    results_subdir = "results"
    if os.path.exists(config_path):
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


class DefaultPolicyAnalyzer:
    """
    Analyzes serverless.yml files to extract IAM policy information
    and generate statistics comparable to dynamic analysis output.
    """

    LANGUAGE_MAP = {
        "javascript": "javascript-typescript",
        "typescript": "javascript-typescript",
        "python": "python",
        "go": "go",
    }

    # Known AWS service prefixes from IAM actions
    KNOWN_SERVICES = {
        's3', 'dynamodb', 'sqs', 'sns', 'lambda', 'kinesis', 'cloudwatch',
        'logs', 'events', 'apigateway', 'cognito-idp', 'cognito-identity',
        'ses', 'secretsmanager', 'ssm', 'kms', 'sts', 'iam', 'ec2', 'rds',
        'cloudformation', 'states', 'stepfunctions', 'rekognition', 'textract',
        'comprehend', 'translate', 'polly', 'transcribe', 'bedrock',
        'appsync', 'athena', 'glue', 'emr', 'elasticache', 'elasticsearch',
        'es', 'firehose', 'cloudfront', 'route53', 'acm', 'waf', 'shield',
        'xray', 'codebuild', 'codepipeline', 'codecommit', 'codedeploy',
        'ecr', 'ecs', 'eks', 'batch', 'sagemaker', 'iot', 'greengrass',
        'mediaconvert', 'mediapackage', 'medialive', 'mediastore',
        'appstream', 'workspaces', 'connect', 'pinpoint', 'mobiletargeting'
    }

    # Wildcard type constants (for actions)
    WILDCARD_FULL = 'full'           # '*' - matches all services and actions
    WILDCARD_SERVICE = 'service'     # '<service>:*' - matches all actions for a service
    WILDCARD_PREFIX = 'prefix'       # '<service>:<prefix>*' - matches actions with prefix
    WILDCARD_NONE = 'none'           # No wildcard - specific action

    # Resource wildcard type constants
    RESOURCE_WILDCARD_FULL = 'full'       # '*' - matches all resources across all services
    RESOURCE_WILDCARD_SERVICE = 'service' # Partially defined ARN targeting all resources of a type
    RESOURCE_WILDCARD_PREFIX = 'prefix'   # Specific resource with wildcard (e.g., bucket/*)

    # Default fallback counts (used only if data files are unavailable)
    DEFAULT_ACTIONS_PER_SERVICE = 50  # Fallback actions per service
    DEFAULT_ACTIONS_PER_PREFIX = 10   # Fallback actions matching a prefix

    def __init__(self, language: str, apps_json_path: str, output_dir: str = None):
        """
        Initialize the Default Policy Analyzer.

        Args:
            language: Programming language of the apps (javascript, python, go, etc.)
            apps_json_path: Path to JSON file containing list of app paths
            output_dir: Output directory for results (default: <output>/results/default_policy_analysis)
        """
        self.language_key = language
        self.apps_json_path = apps_json_path
        self.language = self.LANGUAGE_MAP.get(language, "javascript-typescript")

        # Output directory structure — flat, no language-specific subfolders
        if output_dir is None:
            output_dir = os.path.join(_get_results_dir(), "default_policy_analysis")

        self.output_dir = output_dir
        self.results_path = self.output_dir

        # Stats tracking (flat directory, language only in filename)
        self.stats_output_path = os.path.join(
            self.results_path, f"default_policy_stats_{self.language_key}.jsonl"
        )

        # Create necessary directories
        os.makedirs(self.results_path, exist_ok=True)

        # State file for resume capability
        self.state_file = os.path.join(
            self.results_path, f"processing_state_{self.language_key}.json"
        )

        # Load IAM permission data for accurate wildcard counting
        self._load_iam_permission_data()

    def _load_iam_permission_data(self):
        """
        Load IAM permission data from data files for accurate wildcard counting.

        Loads:
        - permission_count.json: Pre-computed count of permissions per service
        - iam_service_actions.json: Full action details for prefix matching
        """
        # Determine data directory (relative to this script's location)
        # Script is at tools/default_policy_analyzer/ -> tools/ -> project_root/
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(script_dir))
        data_dir = os.path.join(project_root, 'data')

        self.permission_counts = {}  # service -> count
        self.service_actions = {}    # service -> {action_name: [permissions]}
        self.total_permissions = 0   # Sum of all service permissions

        # Load permission counts
        permission_count_path = os.path.join(data_dir, 'permission_count.json')
        if os.path.exists(permission_count_path):
            try:
                with open(permission_count_path, 'r') as f:
                    self.permission_counts = json.load(f)
                self.total_permissions = sum(self.permission_counts.values())
            except Exception as e:
                print(f"Warning: Could not load permission_count.json: {e}")

        # Load full service actions for prefix matching
        iam_actions_path = os.path.join(data_dir, 'iam_service_actions.json')
        if os.path.exists(iam_actions_path):
            try:
                with open(iam_actions_path, 'r') as f:
                    self.service_actions = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load iam_service_actions.json: {e}")

        if self.total_permissions > 0:
            print(f"Loaded IAM data: {len(self.permission_counts)} services, {self.total_permissions} total permissions")
        else:
            print("Warning: Using default permission counts (data files not found)")

    def _get_service_permission_count(self, service: str) -> int:
        """
        Get the number of permissions for a specific AWS service.

        Args:
            service: Service name (lowercase, e.g., 's3', 'dynamodb')

        Returns:
            Number of permissions for the service, or default if unknown
        """
        # Try exact match first
        if service in self.permission_counts:
            return self.permission_counts[service]

        # Try lowercase match
        service_lower = service.lower()
        if service_lower in self.permission_counts:
            return self.permission_counts[service_lower]

        return self.DEFAULT_ACTIONS_PER_SERVICE

    def _get_prefix_permission_count(self, service: str, prefix: str) -> int:
        """
        Count the number of permissions matching a prefix for a service.

        Args:
            service: Service name (e.g., 's3', 'dynamodb')
            prefix: Action prefix (e.g., 'Get', 'Put', 'List')

        Returns:
            Number of permissions matching the prefix
        """
        # Normalize service name for lookup (service_actions uses uppercase keys like "S3", "DynamoDB")
        service_upper = service.upper()
        service_title = service.title()

        # Try different case variations
        actions = None
        for key in [service_upper, service_title, service, service.lower()]:
            if key in self.service_actions:
                actions = self.service_actions[key]
                break

        if not actions:
            return self.DEFAULT_ACTIONS_PER_PREFIX

        # Count actions matching the prefix (case-insensitive)
        prefix_lower = prefix.lower().rstrip('*')
        count = 0
        for action_name in actions.keys():
            if action_name.lower().startswith(prefix_lower):
                # Each action_name maps to a list of permissions
                count += len(actions[action_name])

        return count if count > 0 else self.DEFAULT_ACTIONS_PER_PREFIX

    def find_serverless_yaml(self, project_path: str) -> Optional[str]:
        """
        Recursively find serverless.yml or serverless.yaml in a project.

        Args:
            project_path: Root path of the project

        Returns:
            Path to serverless configuration file or None if not found
        """
        for root, _, files in os.walk(project_path):
            for name in ("serverless.yml", "serverless.yaml"):
                if name in files:
                    return os.path.join(root, name)
        return None

    def _parse_yaml_file(self, yaml_path: str) -> Optional[Dict]:
        """
        Parse a YAML file with support for CloudFormation intrinsic functions.

        Args:
            yaml_path: Path to the YAML file

        Returns:
            Parsed YAML content as dictionary or None on error
        """
        try:
            # Add constructors for CloudFormation intrinsic functions
            yaml.add_multi_constructor('!', lambda loader, suffix, node: None, Loader=yaml.SafeLoader)

            with open(yaml_path, 'r') as f:
                content = yaml.safe_load(f)
            return content
        except yaml.YAMLError as e:
            print(f"YAML parsing error in {yaml_path}: {e}")
            return None
        except Exception as e:
            print(f"Error reading {yaml_path}: {e}")
            return None

    def _extract_functions(self, serverless_config: Dict) -> Dict[str, Dict]:
        """
        Extract function definitions from serverless configuration.

        Args:
            serverless_config: Parsed serverless.yml content

        Returns:
            Dictionary mapping function name -> function config
        """
        functions = serverless_config.get('functions', {})
        if functions is None:
            return {}
        return functions

    def _extract_provider_iam_statements(self, serverless_config: Dict) -> List[Dict]:
        """
        Extract IAM statements defined at the provider level.

        Handles multiple formats:
        - provider.iamRoleStatements (legacy)
        - provider.iam.role.statements (Serverless Framework v3+)
        - provider.iamManagedPolicies (managed policy ARNs)

        Args:
            serverless_config: Parsed serverless.yml content

        Returns:
            List of IAM statement dictionaries
        """
        provider = serverless_config.get('provider', {})
        if not provider:
            return []

        statements = []

        # Legacy format: provider.iamRoleStatements
        iam_role_statements = provider.get('iamRoleStatements', [])
        if iam_role_statements:
            statements.extend(iam_role_statements)

        # New format: provider.iam.role.statements (Serverless Framework v3+)
        iam_config = provider.get('iam', {})
        if isinstance(iam_config, dict):
            role_config = iam_config.get('role', {})
            if isinstance(role_config, dict):
                new_statements = role_config.get('statements', [])
                if new_statements:
                    statements.extend(new_statements)

        return statements

    def _extract_function_iam_statements(self, function_config: Dict) -> Tuple[List[Dict], bool]:
        """
        Extract IAM statements defined at the function level.

        Args:
            function_config: Function configuration dictionary

        Returns:
            Tuple of (list of IAM statements, inherit_from_provider flag)
        """
        statements = []
        inherit = True  # Default to inherit if not specified

        # Check for function-level iamRoleStatements
        iam_role_statements = function_config.get('iamRoleStatements', [])
        if iam_role_statements:
            statements.extend(iam_role_statements)

        # Check for iamRoleStatementsInherit flag
        inherit_flag = function_config.get('iamRoleStatementsInherit')
        if inherit_flag is not None:
            inherit = bool(inherit_flag)

        # If function has its own iamRoleStatements without explicit inherit,
        # check if there's a custom role (which would mean no inheritance)
        if function_config.get('role'):
            inherit = False

        return statements, inherit

    def _normalize_action(self, action: str) -> Tuple[str, str, str]:
        """
        Normalize an IAM action and extract service name.

        Args:
            action: IAM action string (e.g., 's3:GetObject', 'dynamodb:*')

        Returns:
            Tuple of (service_name, action_name, normalized_full_action)
            normalized_full_action has lowercase service prefix (e.g., 's3:GetObject')
        """
        if ':' in action:
            service, action_name = action.split(':', 1)
            service_lower = service.lower()
            normalized_action = f"{service_lower}:{action_name}"
            return service_lower, action_name, normalized_action
        return 'unknown', action, action

    def _is_wildcard_resource(self, resource: str) -> bool:
        """
        Check if a resource ARN contains wildcards.

        Args:
            resource: ARN string

        Returns:
            True if resource contains wildcards
        """
        if not isinstance(resource, str):
            return True  # Non-string resources are treated as wildcards
        return '*' in resource or resource == 'UNKNOWN'

    def _classify_action_wildcard(self, action: str) -> Tuple[str, str, int]:
        """
        Classify the wildcard type of an IAM action.

        Args:
            action: IAM action string (e.g., '*', 's3:*', 's3:Get*', 's3:GetObject')

        Returns:
            Tuple of (wildcard_type, service, effective_permissions_count)
            - wildcard_type: 'full', 'service', 'prefix', or 'none'
            - service: The service name (or '*' for full wildcard)
            - effective_permissions_count: Actual number of permissions granted
        """
        action = action.strip()

        # Full wildcard: '*' matches all services and all actions
        if action == '*':
            # Use actual total permissions from loaded data
            effective_count = self.total_permissions if self.total_permissions > 0 else (
                len(self.permission_counts) * self.DEFAULT_ACTIONS_PER_SERVICE
            )
            return (
                self.WILDCARD_FULL,
                '*',
                effective_count
            )

        if ':' not in action:
            # Treat as full wildcard if no colon
            if '*' in action:
                effective_count = self.total_permissions if self.total_permissions > 0 else (
                    len(self.permission_counts) * self.DEFAULT_ACTIONS_PER_SERVICE
                )
                return (
                    self.WILDCARD_FULL,
                    '*',
                    effective_count
                )
            # Unknown format, treat as single action
            return (self.WILDCARD_NONE, 'unknown', 1)

        service, action_part = action.split(':', 1)
        service_lower = service.lower()

        # Service wildcard: '<service>:*' matches all actions for a service
        if action_part == '*':
            # Use actual permission count for this service
            effective_count = self._get_service_permission_count(service_lower)
            return (
                self.WILDCARD_SERVICE,
                service_lower,
                effective_count
            )

        # Prefix wildcard: '<service>:<prefix>*' matches actions with prefix
        if '*' in action_part:
            # Extract prefix (e.g., 'Get*' -> 'Get', 'GetBucket*' -> 'GetBucket')
            prefix = action_part.split('*')[0]
            # Use actual count of actions matching this prefix
            effective_count = self._get_prefix_permission_count(service_lower, prefix)
            return (
                self.WILDCARD_PREFIX,
                service_lower,
                effective_count
            )

        # No wildcard: specific action
        return (self.WILDCARD_NONE, service_lower, 1)

    def _classify_resource_wildcard(self, resource: str) -> Tuple[str, str]:
        """
        Classify the wildcard type of an IAM resource ARN.

        Resource wildcard types:
        - full: Just '*' - matches all resources across all services
        - service: Wildcard covers ALL top-level resources of a service
                   (e.g., arn:aws:s3:::* = all buckets, arn:aws:dynamodb:*:*:table/* = all tables)
        - prefix: Wildcard within a specific resource or targeting a subset
                  (e.g., arn:aws:s3:::bucket/* = objects in a specific bucket)
        - none: Fully specified resource with no wildcards

        Args:
            resource: Resource ARN string

        Returns:
            Tuple of (wildcard_type, service)
            - wildcard_type: 'full', 'service', 'prefix', or 'none'
            - service: The service name extracted from ARN (or '*' for full wildcard)
        """
        if not isinstance(resource, str):
            # Non-string resources (e.g., CloudFormation refs) treated as prefix wildcards
            return (self.RESOURCE_WILDCARD_PREFIX, 'unknown')

        resource = resource.strip()

        # Full wildcard: just '*' matches everything
        if resource == '*':
            return (self.RESOURCE_WILDCARD_FULL, '*')

        # Check if it's an ARN format
        if not resource.startswith('arn:'):
            # Non-ARN format with wildcard
            if '*' in resource:
                return (self.RESOURCE_WILDCARD_PREFIX, 'unknown')
            return (self.WILDCARD_NONE, 'unknown')

        # Parse ARN: arn:partition:service:region:account:resource
        parts = resource.split(':')
        if len(parts) < 6:
            # Malformed ARN
            if '*' in resource:
                return (self.RESOURCE_WILDCARD_PREFIX, 'unknown')
            return (self.WILDCARD_NONE, 'unknown')

        service = parts[2].lower()
        region = parts[3]
        account = parts[4]
        # Resource part is everything after the 5th colon
        resource_part = ':'.join(parts[5:]) if len(parts) > 5 else parts[5] if len(parts) == 6 else ''

        # No wildcards anywhere = specific resource
        if '*' not in resource and '*' not in region and '*' not in account:
            return (self.WILDCARD_NONE, service)

        # Full resource wildcard = service level (all resources)
        # e.g., arn:aws:s3:::* or arn:aws:sqs:*:*:*
        if resource_part == '*':
            return (self.RESOURCE_WILDCARD_SERVICE, service)

        # Service-specific logic for common patterns
        if service == 's3':
            # S3 ARN format: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/key
            # arn:aws:s3:::* = all buckets (service)
            # arn:aws:s3:::bucket/* = all objects in bucket (prefix - subset)
            # arn:aws:s3:::bucket/folder/* = objects in folder (prefix)
            # arn:aws:s3:::*/* = all objects in all buckets (service)
            # arn:aws:s3:::my-bucket-* = buckets with prefix (prefix)
            if '/' in resource_part:
                bucket_part = resource_part.split('/')[0]
                if bucket_part == '*':
                    # All buckets, all objects = service
                    return (self.RESOURCE_WILDCARD_SERVICE, service)
                else:
                    # Specific bucket, wildcarded objects = prefix
                    return (self.RESOURCE_WILDCARD_PREFIX, service)
            else:
                # No slash, just bucket level
                if resource_part == '*':
                    # Just "*" = all buckets = service
                    return (self.RESOURCE_WILDCARD_SERVICE, service)
                elif '*' in resource_part:
                    # "my-bucket-*" = buckets with prefix = prefix
                    return (self.RESOURCE_WILDCARD_PREFIX, service)
                return (self.WILDCARD_NONE, service)

        # For services with type/name format (DynamoDB, Lambda, SQS, SNS, etc.)
        # e.g., arn:aws:dynamodb:region:account:table/table-name
        # e.g., arn:aws:lambda:region:account:function:function-name
        if '/' in resource_part:
            slash_parts = resource_part.split('/')
            type_part = slash_parts[0]  # e.g., "table", "queue"
            name_part = '/'.join(slash_parts[1:])  # e.g., "my-table", "*"

            if name_part == '*':
                # type/* = all resources of this type
                # Could be service-level or prefix depending on region/account wildcards
                if '*' in region or '*' in account or '*' in type_part:
                    # All resources of type across regions/accounts = service
                    return (self.RESOURCE_WILDCARD_SERVICE, service)
                else:
                    # All resources of type in specific region/account
                    # Still service-level as it covers all tables/functions
                    return (self.RESOURCE_WILDCARD_SERVICE, service)
            elif '*' in name_part:
                # type/prefix* or type/name/sub* = prefix wildcard
                return (self.RESOURCE_WILDCARD_PREFIX, service)
            elif '*' in type_part:
                # */name = unlikely but treat as service
                return (self.RESOURCE_WILDCARD_SERVICE, service)

        # For services with colon-separated format (Lambda function:name)
        if ':' in resource_part:
            colon_parts = resource_part.split(':')
            if len(colon_parts) >= 2:
                type_part = colon_parts[0]  # e.g., "function"
                name_part = ':'.join(colon_parts[1:])  # e.g., "my-func", "*"

                if name_part == '*':
                    return (self.RESOURCE_WILDCARD_SERVICE, service)
                elif '*' in name_part:
                    return (self.RESOURCE_WILDCARD_PREFIX, service)

        # Default: any remaining wildcard is prefix
        if '*' in resource_part or '*' in region or '*' in account:
            return (self.RESOURCE_WILDCARD_PREFIX, service)

        return (self.WILDCARD_NONE, service)

    def _analyze_resource_wildcards(self, resources: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of resources for wildcard usage.

        Args:
            resources: List of resource ARN strings

        Returns:
            Dictionary with resource wildcard analysis flags
        """
        result = {
            'has_full_wildcard': False,
            'has_service_wildcard': False,
            'has_prefix_wildcard': False,
            'full_wildcard_count': 0,
            'service_wildcard_count': 0,
            'prefix_wildcard_count': 0,
            'specific_resource_count': 0,
            'wildcard_resources': [],
            'services_with_wildcards': set(),
            'total_resources': len(resources)
        }

        for resource in resources:
            wildcard_type, service = self._classify_resource_wildcard(resource)

            if wildcard_type == self.RESOURCE_WILDCARD_FULL:
                result['has_full_wildcard'] = True
                result['full_wildcard_count'] += 1
                result['wildcard_resources'].append({
                    'resource': resource,
                    'type': 'full',
                    'service': service
                })
                result['services_with_wildcards'].add(service)
            elif wildcard_type == self.RESOURCE_WILDCARD_SERVICE:
                result['has_service_wildcard'] = True
                result['service_wildcard_count'] += 1
                result['wildcard_resources'].append({
                    'resource': resource,
                    'type': 'service',
                    'service': service
                })
                result['services_with_wildcards'].add(service)
            elif wildcard_type == self.RESOURCE_WILDCARD_PREFIX:
                result['has_prefix_wildcard'] = True
                result['prefix_wildcard_count'] += 1
                result['wildcard_resources'].append({
                    'resource': resource,
                    'type': 'prefix',
                    'service': service
                })
                result['services_with_wildcards'].add(service)
            else:
                result['specific_resource_count'] += 1

        result['has_any_wildcard'] = (
            result['has_full_wildcard'] or
            result['has_service_wildcard'] or
            result['has_prefix_wildcard']
        )

        # Convert set to sorted list for JSON serialization
        result['services_with_wildcards'] = sorted(list(result['services_with_wildcards']))

        return result

    def _analyze_action_wildcards(self, actions: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of actions for wildcard usage.

        Args:
            actions: List of IAM action strings

        Returns:
            Dictionary with wildcard analysis results
        """
        result = {
            'has_full_wildcard': False,
            'has_service_wildcard': False,
            'has_prefix_wildcard': False,
            'full_wildcard_count': 0,
            'service_wildcard_count': 0,
            'prefix_wildcard_count': 0,
            'specific_action_count': 0,
            'wildcard_actions': [],
            'service_wildcards': {},  # service -> count of wildcards
            'effective_permissions': 0,
            'declared_permissions': len(actions)
        }

        for action in actions:
            wildcard_type, service, effective_count = self._classify_action_wildcard(action)
            result['effective_permissions'] += effective_count

            if wildcard_type == self.WILDCARD_FULL:
                result['has_full_wildcard'] = True
                result['full_wildcard_count'] += 1
                result['wildcard_actions'].append({
                    'action': action,
                    'type': 'full',
                    'effective_permissions': effective_count
                })
            elif wildcard_type == self.WILDCARD_SERVICE:
                result['has_service_wildcard'] = True
                result['service_wildcard_count'] += 1
                result['wildcard_actions'].append({
                    'action': action,
                    'type': 'service',
                    'service': service,
                    'effective_permissions': effective_count
                })
                result['service_wildcards'][service] = result['service_wildcards'].get(service, 0) + 1
            elif wildcard_type == self.WILDCARD_PREFIX:
                result['has_prefix_wildcard'] = True
                result['prefix_wildcard_count'] += 1
                result['wildcard_actions'].append({
                    'action': action,
                    'type': 'prefix',
                    'service': service,
                    'effective_permissions': effective_count
                })
                if service not in result['service_wildcards']:
                    result['service_wildcards'][service] = 0
            else:
                result['specific_action_count'] += 1

        result['has_any_wildcard'] = (
            result['has_full_wildcard'] or
            result['has_service_wildcard'] or
            result['has_prefix_wildcard']
        )

        return result

    def _extract_actions_from_statement(self, statement: Dict) -> List[str]:
        """
        Extract all actions from an IAM statement.

        Args:
            statement: IAM statement dictionary

        Returns:
            List of action strings
        """
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            return [actions]
        elif isinstance(actions, list):
            return [a for a in actions if isinstance(a, str)]
        return []

    def _extract_resources_from_statement(self, statement: Dict) -> List[str]:
        """
        Extract all resources from an IAM statement.

        Args:
            statement: IAM statement dictionary

        Returns:
            List of resource ARN strings
        """
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            return [resources]
        elif isinstance(resources, list):
            result = []
            for r in resources:
                if isinstance(r, str):
                    result.append(r)
                elif isinstance(r, dict):
                    # Handle CloudFormation references like Fn::GetAtt, Ref, etc.
                    result.append(str(r))
            return result
        return ['*']  # Default to wildcard if no resource specified

    def _compute_service_usage(self, statements: List[Dict],
                               function_name: str = None) -> Dict[str, Dict]:
        """
        Compute service usage statistics from IAM statements.

        Args:
            statements: List of IAM statement dictionaries
            function_name: Optional function name for context

        Returns:
            Dictionary mapping service -> usage statistics
        """
        service_stats = defaultdict(lambda: {
            'call_count': None,  # Cannot determine from policy
            'unique_actions': set(),
            'action_count': 0,
            'resource_count': 0,
            'wildcard_resources': 0,
            'specific_resources': 0,
            'unresolved_resources': None  # Cannot determine from policy
        })

        for stmt in statements:
            # Skip Deny statements for now (focus on Allow)
            effect = stmt.get('Effect', 'Allow')
            if effect != 'Allow':
                continue

            actions = self._extract_actions_from_statement(stmt)
            resources = self._extract_resources_from_statement(stmt)

            for action in actions:
                service, action_name, _ = self._normalize_action(action)

                service_stats[service]['unique_actions'].add(action_name)
                service_stats[service]['action_count'] = len(service_stats[service]['unique_actions'])

                # Count resources per action
                for resource in resources:
                    service_stats[service]['resource_count'] += 1
                    if self._is_wildcard_resource(resource):
                        service_stats[service]['wildcard_resources'] += 1
                    else:
                        service_stats[service]['specific_resources'] += 1

        # Convert sets to lists for JSON serialization
        result = {}
        for service, stats in service_stats.items():
            result[service] = {
                'call_count': stats['call_count'],
                'unique_actions': sorted(list(stats['unique_actions'])),
                'action_count': stats['action_count'],
                'resource_count': stats['resource_count'],
                'wildcard_resources': stats['wildcard_resources'],
                'specific_resources': stats['specific_resources'],
                'unresolved_resources': stats['unresolved_resources']
            }

        return result

    def _compute_function_metrics(self, function_name: str,
                                  statements: List[Dict]) -> Dict[str, Any]:
        """
        Compute metrics for a single function.

        Args:
            function_name: Name of the function
            statements: IAM statements applicable to this function

        Returns:
            Dictionary with function metrics including wildcard analysis
        """
        services = set()
        permission_count = 0
        resource_count = 0
        wildcard_resources = 0
        specific_resources = 0

        # Collect all actions and resources for wildcard analysis
        all_actions = []
        all_resources = []

        for stmt in statements:
            effect = stmt.get('Effect', 'Allow')
            if effect != 'Allow':
                continue

            actions = self._extract_actions_from_statement(stmt)
            resources = self._extract_resources_from_statement(stmt)

            all_actions.extend(actions)
            all_resources.extend(resources)

            for action in actions:
                service, _, _ = self._normalize_action(action)
                services.add(service)
                permission_count += 1

            for resource in resources:
                resource_count += 1
                if self._is_wildcard_resource(resource):
                    wildcard_resources += 1
                else:
                    specific_resources += 1

        # Analyze action wildcards for this function
        action_wildcard_analysis = self._analyze_action_wildcards(all_actions)

        # Analyze resource wildcards for this function
        resource_wildcard_analysis = self._analyze_resource_wildcards(all_resources)

        return {
            'service_call_count': None,  # Cannot determine from policy
            'unique_services': sorted(list(services)),
            'service_count': len(services),
            'permission_count': permission_count,
            'resource_count': resource_count,
            'wildcard_resources': wildcard_resources,
            'specific_resources': specific_resources,
            'statement_count': len([s for s in statements if s.get('Effect', 'Allow') == 'Allow']),
            # Action wildcard analysis for this function
            'action_wildcard_analysis': {
                'has_any_wildcard': action_wildcard_analysis['has_any_wildcard'],
                'has_full_wildcard': action_wildcard_analysis['has_full_wildcard'],
                'has_service_wildcard': action_wildcard_analysis['has_service_wildcard'],
                'has_prefix_wildcard': action_wildcard_analysis['has_prefix_wildcard'],
                'wildcard_counts': {
                    'full': action_wildcard_analysis['full_wildcard_count'],
                    'service': action_wildcard_analysis['service_wildcard_count'],
                    'prefix': action_wildcard_analysis['prefix_wildcard_count'],
                    'specific': action_wildcard_analysis['specific_action_count']
                },
                'effective_permissions': action_wildcard_analysis['effective_permissions'],
                'declared_permissions': action_wildcard_analysis['declared_permissions'],
                'service_wildcards': action_wildcard_analysis['service_wildcards']
            },
            # Resource wildcard analysis for this function
            'resource_wildcard_analysis': {
                'has_any_wildcard': resource_wildcard_analysis['has_any_wildcard'],
                'has_full_wildcard': resource_wildcard_analysis['has_full_wildcard'],
                'has_service_wildcard': resource_wildcard_analysis['has_service_wildcard'],
                'has_prefix_wildcard': resource_wildcard_analysis['has_prefix_wildcard'],
                'wildcard_counts': {
                    'full': resource_wildcard_analysis['full_wildcard_count'],
                    'service': resource_wildcard_analysis['service_wildcard_count'],
                    'prefix': resource_wildcard_analysis['prefix_wildcard_count'],
                    'specific': resource_wildcard_analysis['specific_resource_count']
                },
                'services_with_wildcards': resource_wildcard_analysis['services_with_wildcards']
            },
            # Legacy fields for backwards compatibility
            'has_any_wildcard': action_wildcard_analysis['has_any_wildcard'],
            'has_full_wildcard': action_wildcard_analysis['has_full_wildcard'],
            'has_service_wildcard': action_wildcard_analysis['has_service_wildcard'],
            'has_prefix_wildcard': action_wildcard_analysis['has_prefix_wildcard'],
            'wildcard_counts': {
                'full': action_wildcard_analysis['full_wildcard_count'],
                'service': action_wildcard_analysis['service_wildcard_count'],
                'prefix': action_wildcard_analysis['prefix_wildcard_count'],
                'specific': action_wildcard_analysis['specific_action_count']
            },
            'effective_permissions': action_wildcard_analysis['effective_permissions'],
            'declared_permissions': action_wildcard_analysis['declared_permissions'],
            'service_wildcards': action_wildcard_analysis['service_wildcards']
        }

    def _compute_permission_stats(self, all_statements: List[Dict],
                                  per_function_statements: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Compute permission-level statistics across all functions.

        Args:
            all_statements: All unique IAM statements
            per_function_statements: Mapping of function -> applicable statements

        Returns:
            Dictionary with permission statistics
        """
        permission_counts = defaultdict(int)
        permission_to_functions = defaultdict(list)

        for func_name, statements in per_function_statements.items():
            for stmt in statements:
                if stmt.get('Effect', 'Allow') != 'Allow':
                    continue

                actions = self._extract_actions_from_statement(stmt)
                for action in actions:
                    _, _, normalized_action = self._normalize_action(action)
                    permission_counts[normalized_action] += 1
                    permission_to_functions[normalized_action].append(func_name)

        # Sort by frequency
        sorted_permissions = sorted(
            permission_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return {
            'total_unique_permissions': len(permission_counts),
            'permission_frequency': dict(sorted_permissions[:20]),
            'permission_distribution': dict(sorted_permissions)
        }

    def _identify_dangerous_permissions(self, per_function_statements: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Identify dangerous/sensitive permissions.

        Args:
            per_function_statements: Mapping of function -> applicable statements

        Returns:
            Dictionary mapping dangerous permissions to usage info
        """
        dangerous_found = {}

        for func_name, statements in per_function_statements.items():
            for stmt in statements:
                if stmt.get('Effect', 'Allow') != 'Allow':
                    continue

                actions = self._extract_actions_from_statement(stmt)
                for action in actions:
                    _, _, normalized_action = self._normalize_action(action)
                    # Check for delete or update permissions
                    action_lower = normalized_action.lower()
                    if 'delete' in action_lower or 'update' in action_lower:
                        if normalized_action not in dangerous_found:
                            dangerous_found[normalized_action] = {
                                'functions': [],
                                'count': 0
                            }
                        dangerous_found[normalized_action]['functions'].append(func_name)
                        dangerous_found[normalized_action]['count'] += 1

        return dangerous_found

    def analyze_serverless_file(self, app_path: str, app_name: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a single serverless.yml file and generate statistics.

        Args:
            app_path: Path to the application directory
            app_name: Name of the application

        Returns:
            Statistics dictionary or None if analysis failed
        """
        # Find serverless.yml
        yaml_path = self.find_serverless_yaml(app_path)
        if not yaml_path:
            print(f"[Skip] {app_name}: No serverless.yml found")
            return None

        # Parse YAML
        config = self._parse_yaml_file(yaml_path)
        if not config:
            print(f"[Error] {app_name}: Failed to parse serverless.yml")
            return None

        # Extract functions
        functions = self._extract_functions(config)
        if not functions:
            print(f"[Skip] {app_name}: No functions defined")
            return None

        # Extract provider-level IAM statements (global)
        provider_statements = self._extract_provider_iam_statements(config)

        # Flag for global IAM statements
        has_global_iam_statements = len(provider_statements) > 0

        # Track function-level IAM statements
        has_function_level_iam_statements = False

        # Build per-function statements
        per_function_statements = {}
        all_statements = list(provider_statements)  # Copy provider statements

        for func_name, func_config in functions.items():
            if not isinstance(func_config, dict):
                func_config = {}

            # Get function-specific statements
            func_statements, inherit = self._extract_function_iam_statements(func_config)

            # Check if any function has its own IAM statements
            if func_statements:
                has_function_level_iam_statements = True

            # Combine statements for this function
            if inherit:
                combined = list(provider_statements) + list(func_statements)
            else:
                combined = list(func_statements)

            per_function_statements[func_name] = combined

            # Add to all statements for global stats
            for stmt in func_statements:
                if stmt not in all_statements:
                    all_statements.append(stmt)

        # Compute statistics
        total_functions = len(functions)
        unique_services = set()
        total_resources = 0
        total_permissions = 0
        total_statements = 0

        # Collect all actions and resources for app-level wildcard analysis
        all_app_actions = []
        all_app_resources = []

        # Aggregate service stats with wildcard tracking
        aggregated_service_usage = defaultdict(lambda: {
            'call_count': None,
            'unique_actions': set(),
            'all_actions': [],  # For wildcard analysis
            'all_resources': [],  # For resource wildcard analysis
            'action_count': 0,
            'resource_count': 0,
            'wildcard_resources': 0,
            'specific_resources': 0,
            'unresolved_resources': None,
            'functions_with_action_wildcards': set(),
            'functions_with_resource_wildcards': set()
        })

        for func_name, statements in per_function_statements.items():
            for stmt in statements:
                if stmt.get('Effect', 'Allow') != 'Allow':
                    continue

                actions = self._extract_actions_from_statement(stmt)
                resources = self._extract_resources_from_statement(stmt)

                total_statements += 1
                total_permissions += len(actions)
                total_resources += len(resources)

                for action in actions:
                    service, action_name, _ = self._normalize_action(action)
                    unique_services.add(service)
                    aggregated_service_usage[service]['unique_actions'].add(action_name)
                    aggregated_service_usage[service]['all_actions'].append(action)
                    all_app_actions.append(action)

                    # Track functions with action wildcards per service
                    wildcard_type, _, _ = self._classify_action_wildcard(action)
                    if wildcard_type != self.WILDCARD_NONE:
                        aggregated_service_usage[service]['functions_with_action_wildcards'].add(func_name)

                for resource in resources:
                    all_app_resources.append(resource)
                    service_for_resource = 'unknown'
                    # Try to extract service from ARN
                    if isinstance(resource, str) and resource.startswith('arn:aws:'):
                        parts = resource.split(':')
                        if len(parts) >= 3:
                            service_for_resource = parts[2]

                    aggregated_service_usage[service_for_resource]['all_resources'].append(resource)

                    # Track resource wildcard type
                    resource_wildcard_type, _ = self._classify_resource_wildcard(resource)
                    if resource_wildcard_type != self.WILDCARD_NONE:
                        aggregated_service_usage[service_for_resource]['functions_with_resource_wildcards'].add(func_name)

                    if self._is_wildcard_resource(resource):
                        aggregated_service_usage[service_for_resource]['wildcard_resources'] += 1
                    else:
                        aggregated_service_usage[service_for_resource]['specific_resources'] += 1
                    aggregated_service_usage[service_for_resource]['resource_count'] += 1

        # Convert service usage to final format with wildcard analysis
        service_usage = {}
        for service, stats in aggregated_service_usage.items():
            # Analyze action wildcards for this service
            service_action_wildcard_analysis = self._analyze_action_wildcards(stats['all_actions'])
            # Analyze resource wildcards for this service
            service_resource_wildcard_analysis = self._analyze_resource_wildcards(stats['all_resources'])

            service_usage[service] = {
                'call_count': stats['call_count'],
                'unique_actions': sorted(list(stats['unique_actions'])),
                'action_count': len(stats['unique_actions']),
                'resource_count': stats['resource_count'],
                'wildcard_resources': stats['wildcard_resources'],
                'specific_resources': stats['specific_resources'],
                'unresolved_resources': stats['unresolved_resources'],
                # Action wildcard analysis for this service
                'action_wildcard_analysis': {
                    'has_any_wildcard': service_action_wildcard_analysis['has_any_wildcard'],
                    'has_service_wildcard': service_action_wildcard_analysis['has_service_wildcard'],
                    'has_prefix_wildcard': service_action_wildcard_analysis['has_prefix_wildcard'],
                    'wildcard_counts': {
                        'service': service_action_wildcard_analysis['service_wildcard_count'],
                        'prefix': service_action_wildcard_analysis['prefix_wildcard_count'],
                        'specific': service_action_wildcard_analysis['specific_action_count']
                    },
                    'effective_permissions': service_action_wildcard_analysis['effective_permissions'],
                    'declared_permissions': service_action_wildcard_analysis['declared_permissions']
                },
                # Resource wildcard analysis for this service
                'resource_wildcard_analysis': {
                    'has_any_wildcard': service_resource_wildcard_analysis['has_any_wildcard'],
                    'has_full_wildcard': service_resource_wildcard_analysis['has_full_wildcard'],
                    'has_service_wildcard': service_resource_wildcard_analysis['has_service_wildcard'],
                    'has_prefix_wildcard': service_resource_wildcard_analysis['has_prefix_wildcard'],
                    'wildcard_counts': {
                        'full': service_resource_wildcard_analysis['full_wildcard_count'],
                        'service': service_resource_wildcard_analysis['service_wildcard_count'],
                        'prefix': service_resource_wildcard_analysis['prefix_wildcard_count'],
                        'specific': service_resource_wildcard_analysis['specific_resource_count']
                    }
                },
                # Legacy fields for backwards compatibility
                'has_any_wildcard': service_action_wildcard_analysis['has_any_wildcard'],
                'has_service_wildcard': service_action_wildcard_analysis['has_service_wildcard'],
                'has_prefix_wildcard': service_action_wildcard_analysis['has_prefix_wildcard'],
                'wildcard_counts': {
                    'service': service_action_wildcard_analysis['service_wildcard_count'],
                    'prefix': service_action_wildcard_analysis['prefix_wildcard_count'],
                    'specific': service_action_wildcard_analysis['specific_action_count']
                },
                'effective_permissions': service_action_wildcard_analysis['effective_permissions'],
                'declared_permissions': service_action_wildcard_analysis['declared_permissions'],
                'functions_with_action_wildcards': sorted(list(stats['functions_with_action_wildcards'])),
                'functions_with_resource_wildcards': sorted(list(stats['functions_with_resource_wildcards']))
            }

        # Compute function metrics (now includes wildcard analysis)
        function_metrics = {}
        for func_name, statements in per_function_statements.items():
            function_metrics[func_name] = self._compute_function_metrics(func_name, statements)

        # Compute permission stats
        permission_stats = self._compute_permission_stats(all_statements, per_function_statements)

        # Identify dangerous permissions
        dangerous_permissions = self._identify_dangerous_permissions(per_function_statements)

        # Count unique statements (deduplicated)
        unique_statement_count = len(all_statements)

        # App-level wildcard analysis
        app_action_wildcard_analysis = self._analyze_action_wildcards(all_app_actions)
        app_resource_wildcard_analysis = self._analyze_resource_wildcards(all_app_resources)

        # Compute aggregate action wildcard stats from functions
        functions_with_action_full_wildcard = []
        functions_with_action_service_wildcard = []
        functions_with_action_prefix_wildcard = []
        functions_with_action_any_wildcard = []

        # Compute aggregate resource wildcard stats from functions
        functions_with_resource_full_wildcard = []
        functions_with_resource_service_wildcard = []
        functions_with_resource_prefix_wildcard = []
        functions_with_resource_any_wildcard = []

        for func_name, metrics in function_metrics.items():
            # Action wildcards
            action_analysis = metrics.get('action_wildcard_analysis', metrics)
            if action_analysis.get('has_full_wildcard'):
                functions_with_action_full_wildcard.append(func_name)
            if action_analysis.get('has_service_wildcard'):
                functions_with_action_service_wildcard.append(func_name)
            if action_analysis.get('has_prefix_wildcard'):
                functions_with_action_prefix_wildcard.append(func_name)
            if action_analysis.get('has_any_wildcard'):
                functions_with_action_any_wildcard.append(func_name)

            # Resource wildcards
            resource_analysis = metrics.get('resource_wildcard_analysis', {})
            if resource_analysis.get('has_full_wildcard'):
                functions_with_resource_full_wildcard.append(func_name)
            if resource_analysis.get('has_service_wildcard'):
                functions_with_resource_service_wildcard.append(func_name)
            if resource_analysis.get('has_prefix_wildcard'):
                functions_with_resource_prefix_wildcard.append(func_name)
            if resource_analysis.get('has_any_wildcard'):
                functions_with_resource_any_wildcard.append(func_name)

        # Compute derived policy flags
        has_both_global_and_function_iam_statements = (
            has_global_iam_statements and has_function_level_iam_statements
        )
        has_no_iam_statements = (
            not has_global_iam_statements and not has_function_level_iam_statements
        )

        # Build final stats structure
        stats = {
            'app_name': app_name,
            'app_path': app_path,
            'timestamp': datetime.now().isoformat(),
            'source': 'serverless.yml',
            'has_global_iam_statements': has_global_iam_statements,
            'has_function_level_iam_statements': has_function_level_iam_statements,
            'has_both_global_and_function_iam_statements': has_both_global_and_function_iam_statements,
            'has_no_iam_statements': has_no_iam_statements,
            'analysis_metrics': {
                'total_functions': total_functions,
                'total_service_calls': None,  # Cannot determine from policy
                'unique_services': sorted(list(unique_services)),
                'service_count': len(unique_services),
                'total_resources': total_resources,
                'resolved_resources': None,  # Cannot determine from policy
                'unresolved_resources': None,  # Cannot determine from policy
                'resolution_rate': None,  # Cannot determine from policy
                'total_statements': unique_statement_count,
                'total_permissions': permission_stats['total_unique_permissions']
            },
            'action_wildcard_analysis': {
                'has_any_wildcard': app_action_wildcard_analysis['has_any_wildcard'],
                'has_full_wildcard': app_action_wildcard_analysis['has_full_wildcard'],
                'has_service_wildcard': app_action_wildcard_analysis['has_service_wildcard'],
                'has_prefix_wildcard': app_action_wildcard_analysis['has_prefix_wildcard'],
                'wildcard_counts': {
                    'full': app_action_wildcard_analysis['full_wildcard_count'],
                    'service': app_action_wildcard_analysis['service_wildcard_count'],
                    'prefix': app_action_wildcard_analysis['prefix_wildcard_count'],
                    'specific': app_action_wildcard_analysis['specific_action_count']
                },
                'total_declared_permissions': app_action_wildcard_analysis['declared_permissions'],
                'total_effective_permissions': app_action_wildcard_analysis['effective_permissions'],
                'wildcard_actions': app_action_wildcard_analysis['wildcard_actions'],
                'services_with_wildcards': list(app_action_wildcard_analysis['service_wildcards'].keys()),
                'functions_with_wildcards': {
                    'any': sorted(functions_with_action_any_wildcard),
                    'full': sorted(functions_with_action_full_wildcard),
                    'service': sorted(functions_with_action_service_wildcard),
                    'prefix': sorted(functions_with_action_prefix_wildcard)
                },
                'functions_with_wildcard_count': len(functions_with_action_any_wildcard),
                'functions_without_wildcard_count': total_functions - len(functions_with_action_any_wildcard)
            },
            'resource_wildcard_analysis': {
                'has_any_wildcard': app_resource_wildcard_analysis['has_any_wildcard'],
                'has_full_wildcard': app_resource_wildcard_analysis['has_full_wildcard'],
                'has_service_wildcard': app_resource_wildcard_analysis['has_service_wildcard'],
                'has_prefix_wildcard': app_resource_wildcard_analysis['has_prefix_wildcard'],
                'wildcard_counts': {
                    'full': app_resource_wildcard_analysis['full_wildcard_count'],
                    'service': app_resource_wildcard_analysis['service_wildcard_count'],
                    'prefix': app_resource_wildcard_analysis['prefix_wildcard_count'],
                    'specific': app_resource_wildcard_analysis['specific_resource_count']
                },
                'total_resources': app_resource_wildcard_analysis['total_resources'],
                'wildcard_resources': app_resource_wildcard_analysis['wildcard_resources'],
                'services_with_wildcards': app_resource_wildcard_analysis['services_with_wildcards'],
                'functions_with_wildcards': {
                    'any': sorted(functions_with_resource_any_wildcard),
                    'full': sorted(functions_with_resource_full_wildcard),
                    'service': sorted(functions_with_resource_service_wildcard),
                    'prefix': sorted(functions_with_resource_prefix_wildcard)
                },
                'functions_with_wildcard_count': len(functions_with_resource_any_wildcard),
                'functions_without_wildcard_count': total_functions - len(functions_with_resource_any_wildcard)
            },
            # Legacy wildcard_analysis field for backwards compatibility (uses action wildcards)
            'wildcard_analysis': {
                'has_any_wildcard': app_action_wildcard_analysis['has_any_wildcard'],
                'has_full_wildcard': app_action_wildcard_analysis['has_full_wildcard'],
                'has_service_wildcard': app_action_wildcard_analysis['has_service_wildcard'],
                'has_prefix_wildcard': app_action_wildcard_analysis['has_prefix_wildcard'],
                'wildcard_counts': {
                    'full': app_action_wildcard_analysis['full_wildcard_count'],
                    'service': app_action_wildcard_analysis['service_wildcard_count'],
                    'prefix': app_action_wildcard_analysis['prefix_wildcard_count'],
                    'specific': app_action_wildcard_analysis['specific_action_count']
                },
                'total_declared_permissions': app_action_wildcard_analysis['declared_permissions'],
                'total_effective_permissions': app_action_wildcard_analysis['effective_permissions'],
                'wildcard_actions': app_action_wildcard_analysis['wildcard_actions'],
                'services_with_wildcards': list(app_action_wildcard_analysis['service_wildcards'].keys()),
                'functions_with_wildcards': {
                    'any': sorted(functions_with_action_any_wildcard),
                    'full': sorted(functions_with_action_full_wildcard),
                    'service': sorted(functions_with_action_service_wildcard),
                    'prefix': sorted(functions_with_action_prefix_wildcard)
                },
                'functions_with_wildcard_count': len(functions_with_action_any_wildcard),
                'functions_without_wildcard_count': total_functions - len(functions_with_action_any_wildcard)
            },
            'service_usage': service_usage,
            'function_metrics': function_metrics,
            'permission_stats': permission_stats,
            'dangerous_permissions': dangerous_permissions
        }

        return stats

    def _load_processed_apps(self) -> Set[str]:
        """Load the set of already processed app paths from the state file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    return set(state.get('processed_apps', []))
            except Exception as e:
                print(f"Warning: Could not load state file: {e}")
        return set()

    def _save_processed_app(self, app_path: str, lock: threading.Lock):
        """Mark an app as processed (thread-safe). Uses app_path for unique identification."""
        with lock:
            processed = self._load_processed_apps()
            processed.add(app_path)

            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump({
                    'processed_apps': list(processed),
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)

    def _reset_processed_apps(self):
        """Clear the processed apps state file."""
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
            print("Cleared processed apps state")

        if os.path.exists(self.stats_output_path):
            os.remove(self.stats_output_path)
            print("Cleared analysis stats file")

    def _save_stats(self, stats: Dict[str, Any], lock: threading.Lock):
        """Save statistics to JSONL file (thread-safe)."""
        with lock:
            os.makedirs(os.path.dirname(self.stats_output_path), exist_ok=True)
            with open(self.stats_output_path, 'a') as f:
                json.dump(stats, f)
                f.write('\n')

    def _process_single_app(self, app_path: str,
                            stats_lock: threading.Lock,
                            state_lock: threading.Lock) -> Dict[str, Any]:
        """
        Process a single application.

        Args:
            app_path: Path to the application
            stats_lock: Lock for stats file writing
            state_lock: Lock for state file writing

        Returns:
            Dictionary with processing result
        """
        app_name = os.path.basename(app_path.rstrip('/'))
        result = {
            'app': app_path,
            'app_name': app_name,
            'status': 'failed'
        }

        try:
            stats = self.analyze_serverless_file(app_path, app_name)

            if stats:
                # Save stats
                self._save_stats(stats, stats_lock)
                self._save_processed_app(app_path, state_lock)
                result['status'] = 'completed'
            else:
                result['status'] = 'no_serverless_or_functions'

        except Exception as e:
            print(f"Error processing {app_name}: {e}")
            import traceback
            traceback.print_exc()
            result['status'] = 'error'
            result['error'] = str(e)

        return result

    def _load_applications(self, path: str) -> List[str]:
        """Load application paths from JSON file."""
        with open(path, 'r') as f:
            apps = json.load(f)
        return apps

    def analyze_projects(self, max_workers: int = 4, resume: bool = True,
                        force_reprocess: bool = False) -> Dict[str, List]:
        """
        Main entrypoint to analyze all projects.

        Args:
            max_workers: Number of concurrent workers
            resume: If True, skip already processed apps
            force_reprocess: If True, reprocess all apps

        Returns:
            Dictionary with analysis results by status
        """
        if not os.path.exists(self.apps_json_path):
            raise FileNotFoundError(f"Apps JSON file not found: {self.apps_json_path}")

        print(f"\n{'='*80}")
        print("DEFAULT POLICY ANALYZER")
        print(f"{'='*80}")
        print(f"Language: {self.language_key}")
        print(f"Apps file: {self.apps_json_path}")
        print(f"Output: {self.results_path}")
        print(f"Workers: {max_workers}")
        print(f"Resume: {resume}")
        print(f"{'='*80}\n")

        # Handle state
        if force_reprocess:
            self._reset_processed_apps()
            processed_apps = set()
        else:
            processed_apps = self._load_processed_apps() if resume else set()

        # Load apps
        all_apps = self._load_applications(self.apps_json_path)

        # Filter already processed (using app_path for unique identification)
        apps_to_process = []
        skipped = []
        for app in all_apps:
            if app in processed_apps:
                print(f"[Resume] Skipping: {os.path.basename(app.rstrip('/'))}")
                skipped.append(app)
            else:
                apps_to_process.append(app)

        print(f"\nTotal apps: {len(all_apps)}")
        print(f"Already processed: {len(processed_apps)}")
        print(f"To process: {len(apps_to_process)}\n")

        if not apps_to_process:
            print("No apps to process.")
            return {'completed': [], 'skipped': skipped, 'failed': [], 'error': []}

        # Initialize result tracking
        results = {
            'completed': [],
            'skipped': skipped,
            'no_serverless_or_functions': [],
            'error': []
        }

        # Locks for thread safety
        stats_lock = threading.Lock()
        state_lock = threading.Lock()

        # Process apps
        start_time = time.perf_counter()
        total = len(apps_to_process)
        completed = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_app = {
                executor.submit(
                    self._process_single_app,
                    app,
                    stats_lock,
                    state_lock
                ): app for app in apps_to_process
            }

            if TQDM_AVAILABLE:
                progress = tqdm(total=total, desc="Analyzing", unit="app")

            for future in as_completed(future_to_app):
                app = future_to_app[future]
                try:
                    result = future.result()
                    status = result['status']

                    if status in results:
                        results[status].append(app)

                    completed += 1

                    if TQDM_AVAILABLE:
                        progress.set_postfix({'app': os.path.basename(app)[:25], 'status': status})
                        progress.update(1)
                    else:
                        print(f"[{completed}/{total}] {os.path.basename(app)}: {status}")

                except Exception as e:
                    print(f"Exception processing {app}: {e}")
                    results['error'].append(app)
                    completed += 1
                    if TQDM_AVAILABLE:
                        progress.update(1)

            if TQDM_AVAILABLE:
                progress.close()

        total_time = time.perf_counter() - start_time

        # Print summary
        print(f"\n{'='*80}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*80}")
        print(f"Total time: {total_time:.2f}s")
        print(f"\nResults:")
        print(f"  Completed: {len(results['completed'])}")
        print(f"  Skipped (already processed): {len(results['skipped'])}")
        print(f"  No serverless/functions: {len(results['no_serverless_or_functions'])}")
        print(f"  Errors: {len(results['error'])}")
        print(f"{'='*80}\n")

        return results

    @staticmethod
    def load_all_stats(stats_file: str) -> List[Dict[str, Any]]:
        """
        Load all statistics from a JSONL file.

        Args:
            stats_file: Path to JSONL file

        Returns:
            List of statistics dictionaries
        """
        if not os.path.exists(stats_file):
            print(f"Stats file not found: {stats_file}")
            return []

        stats_list = []
        with open(stats_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        stats_list.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return stats_list

    def print_stats_summary(self, stats: Dict[str, Any] = None):
        """Print a human-readable summary of statistics."""
        if not stats:
            print("No statistics to display")
            return

        app_name = stats.get('app_name', 'Unknown')
        metrics = stats.get('analysis_metrics', {})
        service_usage = stats.get('service_usage', {})
        permission_stats = stats.get('permission_stats', {})
        dangerous_perms = stats.get('dangerous_permissions', {})

        print(f"\n{'='*60}")
        print(f"Statistics: {app_name}")
        print(f"{'='*60}")

        print("\n[Analysis Metrics]")
        print(f"  Functions: {metrics.get('total_functions', 0)}")
        print(f"  Services: {metrics.get('service_count', 0)}")
        print(f"  Permissions: {metrics.get('total_permissions', 0)}")
        print(f"  Statements: {metrics.get('total_statements', 0)}")

        if service_usage:
            print("\n[Service Usage]")
            for service, usage in sorted(service_usage.items()):
                print(f"  {service}: {usage.get('action_count', 0)} actions, "
                      f"{usage.get('resource_count', 0)} resources")

        if dangerous_perms:
            print("\n[Dangerous Permissions]")
            for perm, info in sorted(dangerous_perms.items()):
                print(f"  {perm}: {info.get('count', 0)} occurrence(s)")

        print(f"{'='*60}\n")

    @classmethod
    def from_cli(cls):
        """Initialize from command line arguments."""
        parser = argparse.ArgumentParser(
            description="Analyze serverless.yml files to extract IAM policy statistics.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Analyze Python serverless apps
  python tools/default_policy_analyzer/privLess_default_policy_analyzer.py --language python --apps-json apps/python_apps.json

  # Analyze with custom output directory
  python tools/default_policy_analyzer/privLess_default_policy_analyzer.py --language javascript --apps-json apps/js_apps.json --output-dir ./output

  # Force reprocess all apps
  python tools/default_policy_analyzer/privLess_default_policy_analyzer.py --language go --apps-json apps/go_apps.json --force-reprocess

  # Run with multiple workers
  python tools/default_policy_analyzer/privLess_default_policy_analyzer.py --language python --apps-json apps.json --workers 8
            """
        )

        parser.add_argument(
            "--language",
            choices=cls.LANGUAGE_MAP.keys(),
            required=True,
            help="Programming language of the apps"
        )
        parser.add_argument(
            "--apps-json",
            required=True,
            help="Path to JSON file containing list of app paths"
        )
        parser.add_argument(
            "--output-dir",
            default=None,
            help="Output directory for results (default: <output>/results/default_policy_analysis)"
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=4,
            help="Number of concurrent workers (default: 4)"
        )
        parser.add_argument(
            "--resume",
            action="store_true",
            default=True,
            help="Resume from previous run (default: True)"
        )
        parser.add_argument(
            "--no-resume",
            dest="resume",
            action="store_false",
            help="Do not resume, process all apps"
        )
        parser.add_argument(
            "--force-reprocess",
            action="store_true",
            help="Force reprocess all apps"
        )

        args = parser.parse_args()

        analyzer = cls(
            language=args.language,
            apps_json_path=args.apps_json,
            output_dir=args.output_dir
        )

        return analyzer, args


def main():
    """Main entry point."""
    analyzer, args = DefaultPolicyAnalyzer.from_cli()

    results = analyzer.analyze_projects(
        max_workers=args.workers,
        resume=args.resume,
        force_reprocess=args.force_reprocess
    )

    # Print summary of all analyzed apps
    print("\nLoading stats for summary...")
    all_stats = DefaultPolicyAnalyzer.load_all_stats(analyzer.stats_output_path)

    if all_stats:
        print(f"\nTotal applications analyzed: {len(all_stats)}")

        # Aggregate statistics
        total_functions = sum(s.get('analysis_metrics', {}).get('total_functions', 0) for s in all_stats)
        total_permissions = sum(s.get('analysis_metrics', {}).get('total_permissions', 0) for s in all_stats)
        total_statements = sum(s.get('analysis_metrics', {}).get('total_statements', 0) for s in all_stats)

        print(f"Total functions: {total_functions}")
        print(f"Total unique permissions: {total_permissions}")
        print(f"Total statements: {total_statements}")

    return 0


if __name__ == "__main__":
    exit(main())
