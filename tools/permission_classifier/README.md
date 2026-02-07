# Permission Classifier

Standalone tool that classifies AWS IAM permissions into security impact categories using heuristic keyword matching. This is independent from the core PrivLess analysis pipeline.

## Overview

The classifier takes AWS IAM permission strings (e.g., `s3:GetObject`, `iam:AttachUserPolicy`) and categorizes each into one of the following security impact categories:

| Category | Description |
|---|---|
| **Reconnaissance** | Read-only metadata operations (`List*`, `Describe*`, `Get*` on non-data resources) |
| **Data Exfiltration** | Read access to data objects (`s3:GetObject`, `dynamodb:GetItem`, etc.) |
| **Credential Access** | Access to secrets, keys, or tokens (`secretsmanager:GetSecretValue`, `kms:Decrypt`) |
| **Privilege Escalation** | IAM policy/role modifications, `sts:AssumeRole`, `lambda:UpdateFunctionCode` |
| **Data Tampering** | Write/modify operations (`Put*`, `Update*`, `Modify*`) |
| **Data Destruction** | Delete operations on data resources (`s3:DeleteObject`, `dynamodb:DeleteTable`) |
| **DoS** | Service disruption actions (`Stop*`, `Terminate*`, `Disable*` on infrastructure) |
| **Resource Hijacking** | Compute resource creation/execution (`ec2:RunInstances`, `lambda:InvokeFunction`) |
| **Defense Evasion** | Disabling security monitoring (`cloudtrail:StopLogging`, `guardduty:Delete*`) |

## How Classification Works

1. **Service-specific overrides** are checked first. Hard-coded rules for services like `iam`, `sts`, `secretsmanager`, `ssm`, `kms`, `lambda`, `cloudtrail`, `guardduty`, and `logs` take highest priority.

2. **Priority-ordered heuristic matching** then evaluates the permission against each category in order:
   - Credential Access (keywords: `secret`, `password`, `key`, `token`, `credential`)
   - Privilege Escalation (IAM/STS services + policy/role keywords)
   - Data Destruction (delete/remove/destroy actions on data services)
   - DoS (stop/terminate/disable on infrastructure keywords)
   - Resource Hijacking (compute services + run/invoke/create actions)
   - Data Exfiltration (get/read actions + data-related keywords like `object`, `item`, `record`)
   - Data Tampering (put/update/modify actions, excluding privilege escalation)
   - Reconnaissance (list/describe/get without data or credential indicators)

3. **Wildcard expansion**: Permissions containing wildcards (`*`, `s3:*`, `s3:Get*`) are expanded to their full list of concrete permissions using `data/iam_service_actions.json` before classification.

## Additional Features

- **Serverless.yml parsing**: Extracts IAM permissions from `provider.iamRoleStatements` (legacy) and `provider.iam.role.statements` (v3+), including function-level statements
- **Batch processing**: Process multiple apps from a JSON manifest file
- **CSV export**: Outputs per-app classification counts

## Output

Results are written to `output/results/permission_classifications/permission_classifications.csv` by default. The output directory is resolved from `config.yaml` (`output.dir` + `output.results_subdir`). Override with `--output`.

## Usage

```bash
# Run built-in classification tests
python tools/permission_classifier/permission_classifier.py --test

# Classify permissions across apps listed in a JSON file (outputs to default location)
python tools/permission_classifier/permission_classifier.py --apps-json apps.json

# Custom output path
python tools/permission_classifier/permission_classifier.py --apps-json apps.json --output /path/to/results.csv
```

## Data Dependencies

- `data/iam_service_actions.json` — Required for wildcard expansion. Looked up automatically relative to the project root.
