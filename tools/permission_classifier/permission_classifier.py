"""
AWS Permission Security Impact Classifier
Uses heuristic keyword matching to categorize AWS IAM permissions

Extended to support:
- Loading serverless apps from combined.json
- Parsing serverless.yml/yaml files
- Extracting global and function-level permissions
- Counting classifications per app
- Exporting results to CSV
"""

from typing import List, Dict, Set, Optional, Tuple, Any
import re
import os
import json
import csv
from collections import defaultdict

# Optional yaml support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Project root: tools/permission_classifier/ -> tools/ -> project_root/
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))


def _get_results_dir() -> str:
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


class AWSPermissionClassifier:
    """
    Classifies AWS permissions into security impact categories using heuristic rules.
    """
    
    # Define keyword patterns for each category
    PATTERNS = {
        'Reconnaissance': {
            'actions': ['list', 'describe', 'get', 'scan', 'query', 'search'],
            'exclusions': ['secret', 'password', 'key', 'token', 'credential'],  # These go to Credential Access
            'data_exclusions': ['object', 'item', 'record', 'file', 'document']  # These go to Data Exfiltration
        },
        'Data Exfiltration': {
            'actions': ['get', 'read', 'download', 'export', 'retrieve', 'fetch', 'select'],
            'data_indicators': ['object', 'item', 'record', 'file', 'document', 'data', 'content', 'body', 'backup']
        },
        'Credential Access': {
            'services': ['secretsmanager', 'ssm', 'kms'],
            'actions': ['get', 'decrypt', 'retrieve'],
            'keywords': ['secret', 'password', 'key', 'token', 'credential', 'parameter']
        },
        'Privilege Escalation': {
            'services': ['iam', 'sts', 'lambda', 'ec2'],
            'actions': ['attach', 'put', 'create', 'update', 'modify', 'add', 'associate'],
            'keywords': ['policy', 'role', 'user', 'group', 'permission', 'assume', 'pass', 'functioncode']
        },
        'Data Tampering': {
            'actions': ['put', 'update', 'modify', 'write', 'edit', 'change', 'replace', 'upload', 'insert'],
            'exclusions': []  # Will be filtered by other rules
        },
        'Data Destruction': {
            'actions': ['delete', 'remove', 'destroy', 'terminate', 'drop'],
            'keywords': ['object', 'item', 'record', 'table', 'bucket', 'function', 'instance', 'volume']
        },
        'DoS': {
            'actions': ['delete', 'stop', 'terminate', 'disable'],
            'keywords': ['function', 'instance', 'cluster', 'service', 'distribution', 'loadbalancer', 
                        'database', 'table', 'queue', 'topic']
        },
        'Resource Hijacking': {
            'services': ['ec2', 'lambda', 'sagemaker', 'batch', 'ecs', 'eks'],
            'actions': ['run', 'invoke', 'create', 'start', 'execute', 'launch'],
            'keywords': ['instance', 'function', 'job', 'task', 'training', 'container']
        }
    }
    
    # Service-specific overrides for edge cases
    SERVICE_OVERRIDES = {
        'iam': {
            'get': 'Reconnaissance',  # iam:GetUser, iam:GetRole → Reconnaissance, not Data Exfiltration
            'list': 'Reconnaissance',
        },
        'sts': {
            'assume': 'Privilege Escalation',
            'get': 'Privilege Escalation',  # sts:GetSessionToken
        },
        'secretsmanager': {
            'get': 'Credential Access',
            'describe': 'Reconnaissance',
            'list': 'Reconnaissance',
        },
        'ssm': {
            'get': 'Credential Access',  # ssm:GetParameter → Credential Access
            'describe': 'Reconnaissance',
            'list': 'Reconnaissance',
        },
        'kms': {
            'decrypt': 'Credential Access',
            'get': 'Reconnaissance',  # kms:GetKeyPolicy
            'list': 'Reconnaissance',
        },
        'lambda': {
            'update': 'Privilege Escalation',  # lambda:UpdateFunctionCode
            'create': 'Privilege Escalation',
            'invoke': 'Resource Hijacking',
        },
        'cloudtrail': {
            'stop': 'Defense Evasion',
            'delete': 'Defense Evasion',
        },
        'guardduty': {
            'delete': 'Defense Evasion',
        },
        'logs': {
            'delete': 'Defense Evasion',
        }
    }
    
    def __init__(self, iam_actions_path: str = None):
        """
        Initialize the classifier.

        Args:
            iam_actions_path: Path to iam_service_actions.json file.
                             If None, will look in ../data/ relative to this file.
        """
        self.service_actions = {}  # service_name (lowercase) -> {action_name: [full_permissions]}
        self.all_permissions = []  # List of all permissions for full wildcard expansion
        self._load_iam_actions_data(iam_actions_path)

    def _load_iam_actions_data(self, iam_actions_path: str = None):
        """
        Load IAM service actions data for wildcard expansion.

        Args:
            iam_actions_path: Path to iam_service_actions.json file
        """
        if iam_actions_path is None:
            # Look for data file relative to this script (tools/permission_classifier/ -> tools/ -> project_root -> data)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(script_dir))
            iam_actions_path = os.path.join(project_root, 'data', 'iam_service_actions.json')

        if not os.path.exists(iam_actions_path):
            print(f"Warning: IAM actions data file not found at {iam_actions_path}")
            print("Wildcard expansion will not be available.")
            return

        try:
            with open(iam_actions_path, 'r') as f:
                raw_data = json.load(f)

            # Process the data into a more usable format
            # Original format: {"ACM": {"addtagstocertificate": ["acm:AddTagsToCertificate"], ...}}
            # We need: {"acm": {"addtagstocertificate": ["acm:AddTagsToCertificate"], ...}}

            for service_key, actions in raw_data.items():
                # Extract the actual service prefix from the first permission
                service_lower = None
                for action_name, perms in actions.items():
                    if perms and len(perms) > 0:
                        # Get service from permission like "acm:AddTagsToCertificate"
                        if ':' in perms[0]:
                            service_lower = perms[0].split(':')[0].lower()
                            break

                if service_lower is None:
                    service_lower = service_key.lower()

                if service_lower not in self.service_actions:
                    self.service_actions[service_lower] = {}

                for action_name, perms in actions.items():
                    self.service_actions[service_lower][action_name.lower()] = perms
                    self.all_permissions.extend(perms)

            # Deduplicate all_permissions
            self.all_permissions = list(set(self.all_permissions))

            print(f"Loaded IAM data: {len(self.service_actions)} services, {len(self.all_permissions)} total permissions")

        except Exception as e:
            print(f"Warning: Failed to load IAM actions data: {e}")
            self.service_actions = {}
            self.all_permissions = []
    
    def _extract_parts(self, permission: str) -> tuple:
        """
        Extract service and action from permission string.
        
        Args:
            permission: AWS permission (e.g., 's3:GetObject')
            
        Returns:
            Tuple of (service, action_lowercase)
        """
        if ':' not in permission:
            return None, None
        
        parts = permission.split(':', 1)
        service = parts[0].lower()
        action = parts[1].lower() if len(parts) > 1 else ''
        
        return service, action
    
    def classify_permission(self, permission: str) -> str:
        """
        Classify a single AWS permission into a security impact category.
        
        Args:
            permission: AWS permission string (e.g., 's3:GetObject')
            
        Returns:
            Category name as string
        """
        service, action = self._extract_parts(permission)
        
        if not service or not action:
            return 'Other'
        
        # Check service-specific overrides first
        if service in self.SERVICE_OVERRIDES:
            for action_pattern, category in self.SERVICE_OVERRIDES[service].items():
                if action_pattern in action:
                    return category
        
        # Priority order for classification (most specific first)
        
        # 1. Credential Access (highest priority for secrets/keys)
        if self._is_credential_access(service, action, permission):
            return 'Credential Access'
        
        # 2. Privilege Escalation (IAM, role, policy operations)
        if self._is_privilege_escalation(service, action, permission):
            return 'Privilege Escalation'
        
        # 3. Data Destruction (explicit delete operations)
        if self._is_data_destruction(service, action, permission):
            return 'Data Destruction'
        
        # 4. DoS (service disruption)
        if self._is_dos(service, action, permission):
            return 'DoS'
        
        # 5. Resource Hijacking (compute resource creation/execution)
        if self._is_resource_hijacking(service, action, permission):
            return 'Resource Hijacking'
        
        # 6. Data Exfiltration (reading data objects)
        if self._is_data_exfiltration(service, action, permission):
            return 'Data Exfiltration'
        
        # 7. Data Tampering (modification operations)
        if self._is_data_tampering(service, action, permission):
            return 'Data Tampering'
        
        # 8. Reconnaissance (default for list/describe/get without data)
        if self._is_reconnaissance(service, action, permission):
            return 'Reconnaissance'
        
        return 'Other'
    
    def _is_credential_access(self, service: str, action: str, permission: str) -> bool:
        """Check if permission is for credential access."""
        patterns = self.PATTERNS['Credential Access']
        
        # Service-specific credential services
        if service in patterns['services']:
            if any(a in action for a in patterns['actions']):
                # Exclude pure reconnaissance
                if not any(x in action for x in ['list', 'describe']):
                    return True
        
        # Keyword-based detection
        if any(kw in action for kw in patterns['keywords']):
            if any(a in action for a in patterns['actions']):
                return True
        
        return False
    
    def _is_privilege_escalation(self, service: str, action: str, permission: str) -> bool:
        """Check if permission enables privilege escalation."""
        patterns = self.PATTERNS['Privilege Escalation']
        
        # IAM/STS operations are high priority
        if service in patterns['services']:
            # Creation or modification of policies/roles
            if any(kw in action for kw in patterns['keywords']):
                if any(a in action for a in patterns['actions']):
                    return True
            
            # Special cases
            if 'passrole' in action.replace('_', '').replace('-', ''):
                return True
            if 'assumerole' in action.replace('_', '').replace('-', ''):
                return True
        
        # Lambda code updates (common escalation vector)
        if service == 'lambda' and 'functioncode' in action:
            return True
        
        return False
    
    def _is_data_destruction(self, service: str, action: str, permission: str) -> bool:
        """Check if permission allows data destruction."""
        patterns = self.PATTERNS['Data Destruction']
        
        # Must have delete/remove/destroy action
        if not any(a in action for a in patterns['actions']):
            return False
        
        # Check for data-related keywords or general destruction
        if any(kw in action for kw in patterns['keywords']):
            return True
        
        # Generic delete on data services
        data_services = ['s3', 'dynamodb', 'rds', 'redshift', 'elasticache', 'documentdb']
        if service in data_services:
            return True
        
        return False
    
    def _is_dos(self, service: str, action: str, permission: str) -> bool:
        """Check if permission can cause denial of service."""
        patterns = self.PATTERNS['DoS']
        
        # Stop/terminate/disable actions on critical services
        if any(a in action for a in patterns['actions']):
            if any(kw in action for kw in patterns['keywords']):
                return True
        
        return False
    
    def _is_resource_hijacking(self, service: str, action: str, permission: str) -> bool:
        """Check if permission enables resource hijacking."""
        patterns = self.PATTERNS['Resource Hijacking']
        
        # Compute services with creation/execution actions
        if service in patterns['services']:
            if any(a in action for a in patterns['actions']):
                if any(kw in action for kw in patterns['keywords']):
                    return True
        
        return False
    
    def _is_data_exfiltration(self, service: str, action: str, permission: str) -> bool:
        """Check if permission allows data exfiltration."""
        patterns = self.PATTERNS['Data Exfiltration']
        
        # Get/Read operations on data objects
        if any(a in action for a in patterns['actions']):
            if any(kw in action for kw in patterns['data_indicators']):
                return True
        
        # Specific data services
        data_services = ['s3', 'dynamodb', 'rds', 'redshift', 'elasticache']
        if service in data_services:
            if any(a in action for a in patterns['actions']):
                return True
        
        return False
    
    def _is_data_tampering(self, service: str, action: str, permission: str) -> bool:
        """Check if permission allows data tampering."""
        patterns = self.PATTERNS['Data Tampering']
        
        # Put/Update/Modify operations
        if any(a in action for a in patterns['actions']):
            # Exclude already classified as privilege escalation
            if not self._is_privilege_escalation(service, action, permission):
                return True
        
        return False
    
    def _is_reconnaissance(self, service: str, action: str, permission: str) -> bool:
        """Check if permission is for reconnaissance."""
        patterns = self.PATTERNS['Reconnaissance']
        
        # List/Describe operations
        if any(a in action for a in patterns['actions']):
            # Exclude if it's actually credential access or data exfiltration
            if not any(kw in action for kw in patterns['exclusions']):
                if not any(kw in action for kw in patterns.get('data_exclusions', [])):
                    return True
        
        return False
    
    def classify_permissions(self, permissions: List[str]) -> Dict[str, List[str]]:
        """
        Classify multiple AWS permissions and group by category.
        
        Args:
            permissions: List of AWS permission strings
            
        Returns:
            Dictionary with categories as keys and lists of permissions as values
        """
        results = {
            'Data Exfiltration': [],
            'Data Tampering': [],
            'Data Destruction': [],
            'Privilege Escalation': [],
            'Reconnaissance': [],
            'Credential Access': [],
            'DoS': [],
            'Resource Hijacking': [],
            'Defense Evasion': [],
            'Other': []
        }
        
        for permission in permissions:
            category = self.classify_permission(permission)
            results[category].append(permission)
        
        # Remove empty categories
        results = {k: v for k, v in results.items() if v}
        
        return results
    
    def get_statistics(self, permissions: List[str]) -> Dict[str, int]:
        """
        Get classification statistics for a list of permissions.

        Args:
            permissions: List of AWS permission strings

        Returns:
            Dictionary with category counts
        """
        classified = self.classify_permissions(permissions)
        return {category: len(perms) for category, perms in classified.items()}

    # ==================== Serverless.yml Parsing Methods ====================

    def find_serverless_yaml(self, project_path: str) -> Optional[str]:
        """
        Find serverless.yml or serverless.yaml in a project directory.

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
        if not YAML_AVAILABLE:
            print("Warning: PyYAML not installed. Install with: pip install pyyaml")
            return None

        try:
            # Add constructors for CloudFormation intrinsic functions
            yaml.add_multi_constructor('!', lambda loader, suffix, node: None, Loader=yaml.SafeLoader)

            with open(yaml_path, 'r') as f:
                content = yaml.safe_load(f)
            return content
        except yaml.YAMLError as e:
            return None
        except Exception as e:
            return None

    def _extract_provider_iam_statements(self, serverless_config: Dict) -> List[Dict]:
        """
        Extract IAM statements defined at the provider level.

        Handles multiple formats:
        - provider.iamRoleStatements (legacy)
        - provider.iam.role.statements (Serverless Framework v3+)

        Args:
            serverless_config: Parsed serverless.yml content

        Returns:
            List of IAM statement dictionaries
        """
        provider = serverless_config.get('provider', {})
        if not provider or not isinstance(provider, dict):
            return []

        statements = []

        # Legacy format: provider.iamRoleStatements
        iam_role_statements = provider.get('iamRoleStatements', [])
        if iam_role_statements and isinstance(iam_role_statements, list):
            for stmt in iam_role_statements:
                if isinstance(stmt, dict):
                    statements.append(stmt)

        # New format: provider.iam.role.statements (Serverless Framework v3+)
        iam_config = provider.get('iam', {})
        if isinstance(iam_config, dict):
            role_config = iam_config.get('role', {})
            if isinstance(role_config, dict):
                new_statements = role_config.get('statements', [])
                if new_statements and isinstance(new_statements, list):
                    for stmt in new_statements:
                        if isinstance(stmt, dict):
                            statements.append(stmt)

        return statements

    def _extract_function_iam_statements(self, function_config: Dict) -> List[Dict]:
        """
        Extract IAM statements defined at the function level.

        Args:
            function_config: Function configuration dictionary

        Returns:
            List of IAM statements for this function
        """
        statements = []

        # Check for function-level iamRoleStatements
        iam_role_statements = function_config.get('iamRoleStatements', [])
        if iam_role_statements and isinstance(iam_role_statements, list):
            for stmt in iam_role_statements:
                if isinstance(stmt, dict):
                    statements.append(stmt)

        return statements

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

    def _expand_wildcard_action(self, action: str) -> List[str]:
        """
        Expand wildcard actions to their full list of permissions.

        Handles three types of wildcards:
        - Full wildcard ('*'): Returns all permissions from all services
        - Service wildcard ('s3:*'): Returns all permissions for that service
        - Prefix wildcard ('s3:Get*'): Returns all permissions matching the prefix

        Args:
            action: IAM action string (may contain wildcards)

        Returns:
            List of expanded permissions, or [action] if no wildcards or no data
        """
        action = action.strip()

        # If no IAM data loaded, return the action as-is
        if not self.service_actions:
            return [action]

        # Full wildcard: '*' matches all services and all actions
        if action == '*':
            return self.all_permissions if self.all_permissions else [action]

        # Check if there's a wildcard
        if '*' not in action:
            return [action]

        # Must have colon for service:action format
        if ':' not in action:
            return [action]

        service, action_part = action.split(':', 1)
        service_lower = service.lower()

        # Service wildcard: 's3:*' matches all actions for that service
        if action_part == '*':
            if service_lower in self.service_actions:
                expanded = []
                for action_name, perms in self.service_actions[service_lower].items():
                    expanded.extend(perms)
                return expanded if expanded else [action]
            return [action]

        # Prefix wildcard: 's3:Get*' matches actions starting with prefix
        if '*' in action_part:
            prefix = action_part.rstrip('*').lower()
            if service_lower in self.service_actions:
                expanded = []
                for action_name, perms in self.service_actions[service_lower].items():
                    if action_name.startswith(prefix):
                        expanded.extend(perms)
                return expanded if expanded else [action]
            return [action]

        return [action]

    def expand_all_wildcards(self, actions: List[str]) -> List[str]:
        """
        Expand all wildcard actions in a list to their full permissions.

        Args:
            actions: List of IAM action strings (may contain wildcards)

        Returns:
            List of expanded permissions (deduplicated)
        """
        expanded = []
        for action in actions:
            expanded.extend(self._expand_wildcard_action(action))

        # Deduplicate while preserving rough order
        seen = set()
        unique = []
        for perm in expanded:
            if perm not in seen:
                seen.add(perm)
                unique.append(perm)

        return unique

    def extract_all_permissions_from_app(self, app_path: str, expand_wildcards: bool = True) -> Tuple[List[str], bool]:
        """
        Extract all permissions (global and function level) from a serverless app.

        Args:
            app_path: Path to the application directory
            expand_wildcards: If True, expand wildcard permissions to full list

        Returns:
            Tuple of (list of permissions, success flag)
        """
        yaml_path = self.find_serverless_yaml(app_path)
        if not yaml_path:
            return [], False

        config = self._parse_yaml_file(yaml_path)
        if not config:
            return [], False

        all_actions = []

        # Extract provider-level (global) IAM statements
        provider_statements = self._extract_provider_iam_statements(config)
        for stmt in provider_statements:
            # Skip non-dict statements
            if not isinstance(stmt, dict):
                continue
            if stmt.get('Effect', 'Allow') == 'Allow':
                actions = self._extract_actions_from_statement(stmt)
                all_actions.extend(actions)

        # Extract function-level IAM statements
        functions = config.get('functions', {})
        if functions and isinstance(functions, dict):
            for func_name, func_config in functions.items():
                if isinstance(func_config, dict):
                    func_statements = self._extract_function_iam_statements(func_config)
                    for stmt in func_statements:
                        # Skip non-dict statements
                        if not isinstance(stmt, dict):
                            continue
                        if stmt.get('Effect', 'Allow') == 'Allow':
                            actions = self._extract_actions_from_statement(stmt)
                            all_actions.extend(actions)

        # Expand wildcards if requested
        if expand_wildcards:
            all_actions = self.expand_all_wildcards(all_actions)

        # Deduplicate while preserving order
        seen = set()
        unique_actions = []
        for action in all_actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)

        return unique_actions, True

    def classify_app_permissions(self, app_path: str) -> Dict[str, Any]:
        """
        Classify all permissions in a serverless app and return counts by category.

        Args:
            app_path: Path to the application directory

        Returns:
            Dictionary with app info and classification counts
        """
        permissions, success = self.extract_all_permissions_from_app(app_path)

        app_name = os.path.basename(app_path.rstrip('/'))

        result = {
            'app_name': app_name,
            'app_path': app_path,
            'success': success,
            'total_permissions': len(permissions),
            'classifications': {}
        }

        if not success or not permissions:
            # Initialize all categories with 0
            categories = [
                'Reconnaissance', 'Data Exfiltration', 'Credential Access',
                'Privilege Escalation', 'Data Tampering', 'Data Destruction',
                'DoS', 'Resource Hijacking', 'Defense Evasion', 'Other'
            ]
            result['classifications'] = {cat: 0 for cat in categories}
            return result

        # Classify permissions and count
        stats = self.get_statistics(permissions)

        # Ensure all categories are present (even if 0)
        categories = [
            'Reconnaissance', 'Data Exfiltration', 'Credential Access',
            'Privilege Escalation', 'Data Tampering', 'Data Destruction',
            'DoS', 'Resource Hijacking', 'Defense Evasion', 'Other'
        ]
        for cat in categories:
            if cat not in stats:
                stats[cat] = 0

        result['classifications'] = stats
        return result

    def process_apps_from_json(self, apps_json_path: str, output_csv_path: str = None) -> List[Dict]:
        """
        Process all apps from a JSON file and classify their permissions.

        Args:
            apps_json_path: Path to JSON file containing list of app paths
            output_csv_path: Path for output CSV file (default: permission_classifications.csv)

        Returns:
            List of classification results for all apps
        """
        if not os.path.exists(apps_json_path):
            raise FileNotFoundError(f"Apps JSON file not found: {apps_json_path}")

        with open(apps_json_path, 'r') as f:
            app_paths = json.load(f)

        print(f"Processing {len(app_paths)} applications...")

        results = []
        processed = 0
        successful = 0

        for app_path in app_paths:
            result = self.classify_app_permissions(app_path)
            results.append(result)

            processed += 1
            if result['success']:
                successful += 1

            if processed % 100 == 0:
                print(f"  Processed {processed}/{len(app_paths)} apps ({successful} successful)")

        print(f"\nCompleted: {processed} apps processed, {successful} successful")

        # Save to CSV
        if output_csv_path is None:
            output_csv_path = 'permission_classifications.csv'

        self._save_results_to_csv(results, output_csv_path)

        return results

    def _save_results_to_csv(self, results: List[Dict], output_path: str):
        """
        Save classification results to a CSV file.

        Args:
            results: List of classification result dictionaries
            output_path: Path for output CSV file
        """
        categories = [
            'Reconnaissance', 'Data Exfiltration', 'Credential Access',
            'Privilege Escalation', 'Data Tampering', 'Data Destruction',
            'DoS', 'Resource Hijacking', 'Defense Evasion', 'Other'
        ]

        # Create header
        fieldnames = ['app_name', 'app_path', 'total_permissions'] + categories

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                row = {
                    'app_name': result['app_name'],
                    'app_path': result['app_path'],
                    'total_permissions': result['total_permissions']
                }

                # Add classification counts
                for cat in categories:
                    row[cat] = result['classifications'].get(cat, 0)

                writer.writerow(row)

        print(f"\nResults saved to: {output_path}")


# Example usage and CLI
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description="AWS Permission Security Impact Classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run basic tests
  python tools/permission_classifier/permission_classifier.py

  # Process apps from combined.json
  python tools/permission_classifier/permission_classifier.py --apps-json apps/dataset/combined.json --output results.csv

  # Process apps with custom output path
  python tools/permission_classifier/permission_classifier.py --apps-json /path/to/apps.json --output /path/to/output.csv
        """
    )

    parser.add_argument(
        "--apps-json",
        help="Path to JSON file containing list of app paths to process"
    )
    default_output = os.path.join(
        _get_results_dir(), "permission_classifications", "permission_classifications.csv"
    )
    parser.add_argument(
        "--output",
        default=default_output,
        help=f"Output CSV file path (default: <output>/results/permission_classifications/permission_classifications.csv)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run basic classification tests"
    )

    args = parser.parse_args()

    classifier = AWSPermissionClassifier()

    if args.apps_json:
        # Process apps from JSON file
        print(f"Loading apps from: {args.apps_json}")
        results = classifier.process_apps_from_json(args.apps_json, args.output)

        # Print summary statistics
        print("\n=== Summary Statistics ===")
        total_apps = len(results)
        successful_apps = sum(1 for r in results if r['success'])
        apps_with_permissions = sum(1 for r in results if r['total_permissions'] > 0)

        print(f"Total apps:               {total_apps}")
        print(f"Successfully parsed:      {successful_apps}")
        print(f"Apps with permissions:    {apps_with_permissions}")

        # Aggregate classification counts
        categories = [
            'Reconnaissance', 'Data Exfiltration', 'Credential Access',
            'Privilege Escalation', 'Data Tampering', 'Data Destruction',
            'DoS', 'Resource Hijacking', 'Defense Evasion', 'Other'
        ]

        print("\n=== Aggregate Permission Counts ===")
        for cat in categories:
            total = sum(r['classifications'].get(cat, 0) for r in results)
            apps_with_cat = sum(1 for r in results if r['classifications'].get(cat, 0) > 0)
            print(f"{cat:25} {total:6} permissions across {apps_with_cat:4} apps")

    elif args.test or not args.apps_json:
        # Run basic tests
        print("=== Single Permission Classification ===")
        test_permissions = [
            's3:GetObject',
            'iam:AttachUserPolicy',
            'dynamodb:DeleteTable',
            'secretsmanager:GetSecretValue',
            'ec2:RunInstances',
            'lambda:InvokeFunction',
            'cloudtrail:StopLogging',
            's3:ListBucket',
            'lambda:UpdateFunctionCode'
        ]

        for perm in test_permissions:
            category = classifier.classify_permission(perm)
            print(f"{perm:40} → {category}")

        print("\n=== Batch Classification ===")
        sample_permissions = [
            's3:GetObject',
            's3:PutObject',
            's3:DeleteObject',
            's3:ListBucket',
            'iam:AttachUserPolicy',
            'iam:CreateUser',
            'iam:ListUsers',
            'dynamodb:GetItem',
            'dynamodb:PutItem',
            'dynamodb:DeleteTable',
            'secretsmanager:GetSecretValue',
            'ssm:GetParameter',
            'kms:Decrypt',
            'ec2:RunInstances',
            'ec2:DescribeInstances',
            'lambda:InvokeFunction',
            'lambda:UpdateFunctionCode',
            'cloudtrail:StopLogging',
            'rds:DeleteDBInstance',
            'sts:AssumeRole'
        ]

        grouped = classifier.classify_permissions(sample_permissions)

        for category, perms in sorted(grouped.items()):
            print(f"\n{category}:")
            for perm in perms:
                print(f"  - {perm}")

        print("\n=== Statistics ===")
        stats = classifier.get_statistics(sample_permissions)
        for category, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            print(f"{category:25} {count:3} permissions")