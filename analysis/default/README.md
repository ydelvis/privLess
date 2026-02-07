# Default Policy Analysis

Notebooks that analyze the IAM policies developers originally declared in their `serverless.yml` files, before any PrivLess optimization.

## Notebooks

### policy_analysis.ipynb

Analyzes the structure and scope of default IAM policies across all applications.

**Input:** `output/results/default_policy_analysis/combined_default_policy_stats.jsonl`

Key analyses:
- Policy type distribution (global-only, per-function, both, none)
- Action wildcard breakdown (full `*`, service-level `s3:*`, prefix `s3:Get*`, specific)
- Resource wildcard breakdown (full `*`, service-scoped, prefix-scoped)
- AWS service usage distribution across apps
- Dangerous permission identification (`delete`/`update` operations)

### permission_classification.ipynb

Classifies declared permissions into security impact categories.

**Input:** `output/results/permission_classifications/permission_classifications.csv`

Key analyses:
- Distribution across 9 security categories (Reconnaissance, Data Exfiltration, Credential Access, Privilege Escalation, Data Tampering, Data Destruction, DoS, Resource Hijacking, Defense Evasion)
- Per-app classification counts
- High-risk permission analysis
- Category correlation matrix

## Running

Make sure you have completed the prerequisite steps described in the [parent README](../README.md), then open the notebooks in Jupyter:

```bash
cd analysis/default
jupyter notebook
```
