#!/usr/bin/env python3
"""
Dataset Analyzer for PrivLess Statistics

Provides analysis capabilities for aggregating and analyzing statistics
collected from multiple serverless applications.
"""

import json
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple
import os


class Analyzer:
    """
    Analyzer for PrivLess statistics across multiple applications.

    Provides methods to:
    - Aggregate statistics from multiple applications
    - Identify over-privilege patterns
    - Analyze service usage trends
    - Detect dangerous permission usage
    - Generate summary reports
    """

    def __init__(self, stats_file: str = None):
        """
        Initialize the analyzer.

        Args:
            stats_file: Path to JSONL file containing application statistics
        """
        self.stats_file = stats_file
        self.app_stats: List[Dict[str, Any]] = []

        if stats_file and os.path.exists(stats_file):
            self.load_stats(stats_file)

    def load_stats(self, stats_file: str):
        """
        Load statistics from a JSONL file.

        Args:
            stats_file: Path to JSONL file
        """
        self.app_stats = []

        try:
            with open(stats_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        stats = json.loads(line)
                        self.app_stats.append(stats)
                    except json.JSONDecodeError as e:
                        print(f"Warning: Skipping malformed JSON on line {line_num}: {e}")

            print(f"✓ Loaded statistics for {len(self.app_stats)} applications")

        except Exception as e:
            print(f"Error loading statistics: {e}")

    def get_service_usage_summary(self) -> Dict[str, Any]:
        """
        Aggregate service usage across all applications.

        Returns:
            Dictionary with service usage statistics
        """
        service_counts = Counter()
        service_actions = defaultdict(set)
        service_calls = defaultdict(int)

        for app_stats in self.app_stats:
            # Count unique services
            for service in app_stats['analysis_metrics']['unique_services']:
                service_counts[service] += 1

            # Track actions per service
            for service, data in app_stats.get('service_usage', {}).items():
                for action in data.get('unique_actions', []):
                    service_actions[service].add(action)
                service_calls[service] += data.get('call_count', 0)

        return {
            'total_apps': len(self.app_stats),
            'service_frequency': dict(service_counts.most_common()),
            'total_calls_per_service': dict(service_calls),
            'unique_actions_per_service': {
                service: len(actions) for service, actions in service_actions.items()
            }
        }

    def get_overprivilege_analysis(self, wildcard_threshold: float = 0.3) -> Dict[str, Any]:
        """
        Analyze over-privilege patterns based on wildcard resource usage.

        Args:
            wildcard_threshold: Ratio above which an app is considered over-privileged

        Returns:
            Dictionary with over-privilege statistics
        """
        overprivileged_apps = []
        wildcard_ratios = []

        for app_stats in self.app_stats:
            app_name = app_stats['app_name']
            total_wildcards = 0
            total_specific = 0

            for service, data in app_stats.get('service_usage', {}).items():
                total_wildcards += data.get('wildcard_resources', 0)
                total_specific += data.get('specific_resources', 0)

            total_resources = total_wildcards + total_specific
            if total_resources > 0:
                wildcard_ratio = total_wildcards / total_resources
                wildcard_ratios.append(wildcard_ratio)

                if wildcard_ratio > wildcard_threshold:
                    overprivileged_apps.append({
                        'app': app_name,
                        'wildcard_ratio': wildcard_ratio,
                        'total_resources': total_resources,
                        'wildcard_resources': total_wildcards,
                        'specific_resources': total_specific
                    })

        # Sort by wildcard ratio descending
        overprivileged_apps.sort(key=lambda x: x['wildcard_ratio'], reverse=True)

        return {
            'total_apps': len(self.app_stats),
            'overprivileged_count': len(overprivileged_apps),
            'overprivileged_percentage': len(overprivileged_apps) / len(self.app_stats) * 100 if self.app_stats else 0,
            'average_wildcard_ratio': sum(wildcard_ratios) / len(wildcard_ratios) if wildcard_ratios else 0,
            'overprivileged_apps': overprivileged_apps
        }

    def get_permission_distribution(self) -> Dict[str, Any]:
        """
        Analyze permission distribution across applications.

        Returns:
            Dictionary with permission statistics
        """
        perm_counts = []
        all_permissions = Counter()

        for app_stats in self.app_stats:
            perm_count = app_stats['analysis_metrics']['total_permissions']
            perm_counts.append(perm_count)

            # Track individual permissions
            perm_freq = app_stats.get('permission_stats', {}).get('permission_distribution', {})
            for perm in perm_freq.keys():
                all_permissions[perm] += 1

        if perm_counts:
            perm_counts.sort()
            n = len(perm_counts)

            return {
                'total_apps': n,
                'min_permissions': min(perm_counts),
                'max_permissions': max(perm_counts),
                'avg_permissions': sum(perm_counts) / n,
                'median_permissions': perm_counts[n // 2],
                'p25_permissions': perm_counts[n // 4],
                'p75_permissions': perm_counts[3 * n // 4],
                'p90_permissions': perm_counts[int(0.9 * n)],
                'most_common_permissions': dict(all_permissions.most_common(20))
            }

        return {}

    def get_dangerous_permissions_analysis(self) -> Dict[str, Any]:
        """
        Analyze usage of dangerous permissions across applications.

        Returns:
            Dictionary mapping dangerous permissions to apps using them
        """
        dangerous_perm_usage = defaultdict(list)
        apps_with_dangerous = set()

        for app_stats in self.app_stats:
            app_name = app_stats['app_name']
            dangerous_perms = app_stats.get('dangerous_permissions', {})

            if dangerous_perms:
                apps_with_dangerous.add(app_name)

                for perm, info in dangerous_perms.items():
                    dangerous_perm_usage[perm].append({
                        'app': app_name,
                        'count': info.get('count', 0),
                        'functions': info.get('functions', [])
                    })

        # Sort by frequency
        sorted_dangerous = sorted(
            dangerous_perm_usage.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )

        return {
            'total_apps': len(self.app_stats),
            'apps_with_dangerous_permissions': len(apps_with_dangerous),
            'dangerous_permission_usage_rate': len(apps_with_dangerous) / len(self.app_stats) * 100 if self.app_stats else 0,
            'dangerous_permissions_by_frequency': {
                perm: {
                    'app_count': len(apps),
                    'apps': apps
                }
                for perm, apps in sorted_dangerous
            }
        }

    def get_function_level_analysis(self) -> Dict[str, Any]:
        """
        Analyze function-level metrics across all applications.

        Returns:
            Dictionary with function-level statistics
        """
        perms_per_function = []
        services_per_function = []

        for app_stats in self.app_stats:
            function_metrics = app_stats.get('function_metrics', {})

            for func_name, metrics in function_metrics.items():
                perms_per_function.append(metrics.get('permission_count', 0))
                services_per_function.append(metrics.get('service_count', 0))

        if perms_per_function:
            perms_per_function.sort()
            n = len(perms_per_function)

            return {
                'total_functions': n,
                'avg_permissions_per_function': sum(perms_per_function) / n,
                'median_permissions_per_function': perms_per_function[n // 2],
                'max_permissions_per_function': max(perms_per_function),
                'avg_services_per_function': sum(services_per_function) / len(services_per_function),
                'median_services_per_function': sorted(services_per_function)[len(services_per_function) // 2]
            }

        return {}

    def get_resolution_quality_analysis(self) -> Dict[str, Any]:
        """
        Analyze resource resolution quality across applications.

        Returns:
            Dictionary with resolution statistics
        """
        resolution_rates = []
        apps_by_resolution = {
            'high': [],      # > 80% resolved
            'medium': [],    # 50-80% resolved
            'low': [],       # < 50% resolved
        }

        for app_stats in self.app_stats:
            app_name = app_stats['app_name']
            resolution_rate = app_stats['analysis_metrics'].get('resolution_rate', 0)
            resolution_rates.append(resolution_rate)

            if resolution_rate > 0.8:
                apps_by_resolution['high'].append(app_name)
            elif resolution_rate > 0.5:
                apps_by_resolution['medium'].append(app_name)
            else:
                apps_by_resolution['low'].append(app_name)

        return {
            'total_apps': len(self.app_stats),
            'avg_resolution_rate': sum(resolution_rates) / len(resolution_rates) if resolution_rates else 0,
            'high_resolution_apps': len(apps_by_resolution['high']),
            'medium_resolution_apps': len(apps_by_resolution['medium']),
            'low_resolution_apps': len(apps_by_resolution['low']),
            'apps_by_resolution_quality': apps_by_resolution
        }

    def print_comprehensive_report(self):
        """
        Print a comprehensive analysis report.
        """
        if not self.app_stats:
            print("No statistics loaded. Load a stats file first.")
            return

        print("\n" + "=" * 100)
        print("DATASET ANALYSIS REPORT")
        print("=" * 100)

        # Service Usage
        print("\n[SERVICE USAGE]")
        service_summary = self.get_service_usage_summary()
        print(f"Total Applications: {service_summary['total_apps']}")
        print(f"\nMost Common Services:")
        for service, count in list(service_summary['service_frequency'].items())[:10]:
            percentage = count / service_summary['total_apps'] * 100
            print(f"  {service}: {count} apps ({percentage:.1f}%)")

        # Over-Privilege
        print("\n[OVER-PRIVILEGE ANALYSIS]")
        overprivilege = self.get_overprivilege_analysis()
        print(f"Average Wildcard Ratio: {overprivilege['average_wildcard_ratio']:.1%}")
        print(f"Over-privileged Apps (>30% wildcards): {overprivilege['overprivileged_count']} " +
              f"({overprivilege['overprivileged_percentage']:.1f}%)")
        if overprivilege['overprivileged_apps']:
            print("\nTop 5 Over-privileged Apps:")
            for app in overprivilege['overprivileged_apps'][:5]:
                print(f"  {app['app']}: {app['wildcard_ratio']:.1%} wildcards " +
                      f"({app['wildcard_resources']}/{app['total_resources']} resources)")

        # Permission Distribution
        print("\n[PERMISSION DISTRIBUTION]")
        perm_dist = self.get_permission_distribution()
        if perm_dist:
            print(f"Applications: {perm_dist['total_apps']}")
            print(f"Average Permissions: {perm_dist['avg_permissions']:.1f}")
            print(f"Median Permissions: {perm_dist['median_permissions']}")
            print(f"Range: {perm_dist['min_permissions']} - {perm_dist['max_permissions']}")
            print(f"Percentiles: P25={perm_dist['p25_permissions']}, " +
                  f"P75={perm_dist['p75_permissions']}, P90={perm_dist['p90_permissions']}")

            print("\nMost Common Permissions (Top 10):")
            for perm, count in list(perm_dist['most_common_permissions'].items())[:10]:
                percentage = count / perm_dist['total_apps'] * 100
                print(f"  {perm}: {count} apps ({percentage:.1f}%)")

        # Dangerous Permissions
        print("\n[DANGEROUS PERMISSIONS]")
        dangerous = self.get_dangerous_permissions_analysis()
        print(f"Apps with Dangerous Permissions: {dangerous['apps_with_dangerous_permissions']} " +
              f"({dangerous['dangerous_permission_usage_rate']:.1f}%)")

        dangerous_perms = dangerous['dangerous_permissions_by_frequency']
        if dangerous_perms:
            print("\nMost Common Dangerous Permissions:")
            for perm, data in list(dangerous_perms.items())[:10]:
                print(f"  {perm}: {data['app_count']} apps")

        # Function-Level
        print("\n[FUNCTION-LEVEL ANALYSIS]")
        func_analysis = self.get_function_level_analysis()
        if func_analysis:
            print(f"Total Functions: {func_analysis['total_functions']}")
            print(f"Avg Permissions per Function: {func_analysis['avg_permissions_per_function']:.1f}")
            print(f"Median Permissions per Function: {func_analysis['median_permissions_per_function']}")
            print(f"Max Permissions in a Function: {func_analysis['max_permissions_per_function']}")
            print(f"Avg Services per Function: {func_analysis['avg_services_per_function']:.1f}")

        # Resolution Quality
        print("\n[RESOURCE RESOLUTION QUALITY]")
        resolution = self.get_resolution_quality_analysis()
        print(f"Average Resolution Rate: {resolution['avg_resolution_rate']:.1%}")
        print(f"High Resolution (>80%): {resolution['high_resolution_apps']} apps")
        print(f"Medium Resolution (50-80%): {resolution['medium_resolution_apps']} apps")
        print(f"Low Resolution (<50%): {resolution['low_resolution_apps']} apps")

        print("\n" + "=" * 100 + "\n")

    def export_summary(self, output_file: str):
        """
        Export analysis summary to JSON file.

        Args:
            output_file: Path to output JSON file
        """
        summary = {
            'dataset_info': {
                'total_apps': len(self.app_stats),
                'stats_file': self.stats_file
            },
            'service_usage': self.get_service_usage_summary(),
            'overprivilege_analysis': self.get_overprivilege_analysis(),
            'permission_distribution': self.get_permission_distribution(),
            'dangerous_permissions': self.get_dangerous_permissions_analysis(),
            'function_level': self.get_function_level_analysis(),
            'resolution_quality': self.get_resolution_quality_analysis()
        }

        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"✓ Summary exported to {output_file}")


def main():
    """CLI entry point for analyzer."""
    import argparse

    parser = argparse.ArgumentParser(description='Analyze PrivLess statistics')
    parser.add_argument('stats_file', help='JSONL file with application statistics')
    parser.add_argument('-o', '--output', help='Export summary to JSON file')

    args = parser.parse_args()

    analyzer = Analyzer(args.stats_file)
    analyzer.print_comprehensive_report()

    if args.output:
        analyzer.export_summary(args.output)


if __name__ == '__main__':
    main()
