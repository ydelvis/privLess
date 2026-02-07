# PrivLess Core Pipeline

The core analysis engine that uses CodeQL to extract AWS service calls from serverless application source code and generates tightly-scoped IAM policies based on actual code usage, enabling over-privilege analysis.

## How It Works

1. **Database Creation** — CodeQL creates a database from the application source code.
2. **Service Call Extraction** — A CodeQL query identifies all AWS SDK service calls (e.g., `s3.putObject`, `dynamodb.getItem`).
3. **Resource Resolution** — A second CodeQL query performs data-flow analysis to resolve the resource parameters (bucket names, table names, etc.) passed to each service call.
4. **Value Post-Processing** — For JavaScript/TypeScript, truncated string values from CodeQL output are resolved by reading the original source files.
5. **Environment Variable Resolution** — Resource values referencing environment variables are resolved from the `serverless.yml` configuration.
6. **Policy Generation** — Service calls and resolved resources are mapped to IAM actions and ARNs to produce minimal per-function IAM policies.

## Usage

All commands are run from the `src/` directory:

```bash
cd src
python privLess.py [OPTIONS]
```

### CLI Options

| Flag                  | Description                                    |
| --------------------- | ---------------------------------------------- |
| `--config PATH`       | Path to config.yaml                            |
| `--language LANG`     | Override language (javascript/python/go/etc.)   |
| `--apps-json PATH`    | Override apps JSON file path                   |
| `--output-dir PATH`   | Override output directory                      |
| `--workers N`         | Override number of concurrent workers          |
| `--output-format FMT` | Override output format (json/yaml)             |
| `--resume`            | Resume from previous run                       |
| `--no-resume`         | Force process all apps                         |
| `--force-reprocess`   | Clear state and reprocess everything           |

All options have defaults in `config.yaml`; CLI flags override them.

### Examples

```bash
# Use all defaults from config.yaml
python privLess.py

# Analyze JavaScript apps
python privLess.py --language javascript --apps-json ../apps_javascript.json

# Analyze Python apps
python privLess.py --language python --apps-json ../apps_python.json

# Custom output directory with YAML format
python privLess.py --output-dir /path/to/output --output-format yaml

# Force full reprocess with 8 workers
python privLess.py --force-reprocess --workers 8

# Use a different config file
python privLess.py --config /path/to/my-config.yaml
```

## Input

An `apps.json` file listing the paths to serverless application directories:

```json
[
  "/path/to/serverless-app-1",
  "/path/to/serverless-app-2"
]
```

Each path should contain a `serverless.yml` or `serverless.yaml` file.

To generate per-language app lists from the dataset:

```bash
python ../scripts/generate_apps_json.py
```

## Output

Results are written under `output/` (configurable via `config.yaml`):

```
output/
  databases/<language>/             # CodeQL databases (one per app)
    db_<app-name>/
  results/
    service_calls/<language>/       # Extracted service call CSVs
      <app-name>.csv
    resolved_resources/<language>/  # Resource resolution CSVs
      <app-name>.csv
    policies/<language>/            # Generated IAM policies
      <app-name>_policy.yml
    stats/<codeql-language>/        # Per-language analysis statistics
      analysis_stats.jsonl          #   Per-app metrics (JSONL)
      analysis_stats-time.csv       #   Pipeline stage runtimes
      processing_state.json         #   Resume checkpoint
  logs/
    privless.log                    # Main orchestrator
    codeql.log                      # CodeQL DB creation and queries
    extractor.log                   # Service call extraction
    resolver.log                    # Resource resolution
    policy_generator.log            # Policy generation
```

## Testing with the Case Study App

A sample Node.js serverless app is included at `case-study-app/aws-node-http-api-dynamodb-local/`:

```bash
echo '["case-study-app/aws-node-http-api-dynamodb-local"]' > ../apps.json
python privLess.py --language javascript --apps-json ../apps.json
```

The generated policy will appear at `output/results/policies/javascript/aws-node-http-api-dynamodb-local_policy.yml`.

## Bulk Analysis of the Dataset

The `dataset/` directory contains 600 serverless applications. To analyze them in bulk:

### 1. Generate per-language app lists

From the project root, run the helper script that scans each app's `serverless.yml` for its `runtime` field and groups them by language:

```bash
python scripts/generate_apps_json.py
```

This produces:

- `apps_javascript.json` — all Node.js / TypeScript apps
- `apps_python.json` — all Python apps
- `apps_go.json` — all Go apps

### 2. Run PrivLess for each language

```bash
cd src

# JavaScript / TypeScript
python privLess.py --language javascript --apps-json ../apps_javascript.json

# Python
python privLess.py --language python --apps-json ../apps_python.json

# Go
python privLess.py --language go --apps-json ../apps_go.json
```

Each run is resumable by default — if interrupted, re-running the same command picks up where it left off. Use `--force-reprocess` to start fresh.

### 3. Combine results

After all languages have been processed, merge the per-language output into combined files for cross-language analysis:

```bash
cd ..
python tools/combine_results.py
```

The combined files are written to `output/results/` and are ready for use by the analysis notebooks (see [analysis/README.md](../analysis/README.md)).

## Source Files

| File                             | Role                              |
| -------------------------------- | --------------------------------- |
| `privLess.py`                    | Main entry point and orchestrator |
| `privLess_extractor.py`          | Service call extraction via CodeQL |
| `privLess_resolver.py`           | Resource value resolution          |
| `privLess_policyGenerator.py`    | IAM policy generation              |
| `privLess_analyzer.py`           | Post-analysis statistics           |
| `utils/config.py`               | Configuration loader               |
| `utils/log.py`                   | Per-module logging setup           |
| `utils/codeql_agent.py`         | CodeQL CLI wrapper                 |
| `utils/postprocess_truncated_values.py` | Source value extraction     |

## Logging

Each module writes to its own log file in `output/logs/`. Set `logging.level` to `DEBUG` in `config.yaml` for verbose output during troubleshooting.
