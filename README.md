# PrivLess

**Least-privilege IAM policy generator for serverless applications.**

PrivLess uses [CodeQL](https://codeql.github.com/) static analysis to extract AWS service calls from serverless application source code and generates minimal IAM policies scoped to only the permissions each function actually needs.

## Supported Languages

| Language             | Status |
| -------------------- | ------ |
| JavaScript/TypeScript | Supported |
| Python               | Supported |
| Go                   | Supported |
| C#                   | Supported |

## Prerequisites

- **Python 3.8+**
- **CodeQL CLI** installed and available in your PATH (or set the path in `config.yaml`)
  - Install: https://github.com/github/codeql-cli-binaries/releases
  - After downloading, either add it to your PATH or set `codeql.executable` in `config.yaml`
- **pip** (for installing Python dependencies)

## Installation

```bash
# Clone the repository
git clone <repo-url> privLess
cd privLess

# Install Python dependencies
pip install -r requirements.txt
```

## Quick Start

1. **Configure** - Edit `config.yaml` in the project root (see [Configuration](#configuration) below).

2. **Prepare your apps list** - Create a JSON file listing the paths to the serverless applications you want to analyze:

   ```json
   [
     "/path/to/serverless-app-1",
     "/path/to/serverless-app-2"
   ]
   ```

   Each path should point to a directory containing a `serverless.yml` or `serverless.yaml` file.

3. **Run the analysis**:

   ```bash
   cd src
   python privLess.py
   ```

## Testing with the Case Study App

A sample Node.js serverless application (`case-study-app/aws-node-http-api-dynamodb-local`) is included for testing. To run PrivLess against it:

```bash
# 1. Create an apps list pointing to the case study app
echo '["case-study-app/aws-node-http-api-dynamodb-local"]' > apps.json

# 2. Run the analysis
cd src
python privLess.py --language javascript --apps-json ../apps.json
```

The generated policy will be written to `output/results/policies/javascript/` and logs to `output/logs/`.

## Bulk Analysis of the Dataset

The `dataset/` directory contains 600 serverless applications. To analyze them in bulk, first generate per-language app lists using the helper script:

```bash
python scripts/generate_apps_json.py
```

This scans every app's `serverless.yml` for its `runtime` field and produces:

- `apps_javascript.json` - all Node.js apps
- `apps_python.json` - all Python apps
- `apps_go.json` - all Go apps

Then run PrivLess against a language group:

```bash
cd src
python privLess.py --language javascript --apps-json ../apps_javascript.json
python privLess.py --language python --apps-json ../apps_python.json
python privLess.py --language go --apps-json ../apps_go.json
```

## Configuration

All settings are in `config.yaml` at the project root. CLI arguments override config values.

```yaml
# CodeQL executable path (set to "codeql" to use system PATH)
codeql:
  executable: "codeql"

# Analysis settings
analysis:
  language: "javascript"      # javascript, typescript, python, go, csharp
  apps_json: "apps.json"      # JSON file listing app paths to analyze
  workers: 4                  # Number of concurrent analysis workers
  resume: true                # Skip already-processed apps on re-run
  output_format: "yaml"       # "json" or "yaml"

# Output directories (relative to project root)
output:
  dir: "output"
  databases_subdir: "databases"
  results_subdir: "results"
  policies_subdir: "policies"
  stats_subdir: "stats"
  logs_subdir: "logs"

# Data files
data:
  permission_map: "data/iam_service_actions.json"

# Logging
logging:
  level: "INFO"               # DEBUG, INFO, WARNING, ERROR, CRITICAL
  console_output: true        # Also print logs to console
  files:
    main: "privless.log"
    codeql: "codeql.log"
    extractor: "extractor.log"
    resolver: "resolver.log"
    policy_generator: "policy_generator.log"
```

### Key Configuration Options

| Setting               | Description                                               | Default     |
| --------------------- | --------------------------------------------------------- | ----------- |
| `codeql.executable`   | Path to CodeQL binary, or `"codeql"` to use system PATH   | `"codeql"`  |
| `analysis.language`   | Language of the serverless apps                           | `"javascript"` |
| `analysis.apps_json`  | JSON file with list of app paths                          | `"apps.json"` |
| `analysis.workers`    | Parallel processing threads                               | `4`         |
| `analysis.resume`     | Resume from previous run                                  | `true`      |
| `analysis.output_format` | Policy output format                                   | `"yaml"`    |
| `output.dir`          | Base output directory                                     | `"output"`  |
| `logging.level`       | Log verbosity                                             | `"INFO"`    |

## CLI Usage

```
python privLess.py [OPTIONS]
```

### Options

| Flag                 | Description                                    |
| -------------------- | ---------------------------------------------- |
| `--config PATH`      | Path to config.yaml                            |
| `--language LANG`    | Override language (javascript/python/go/etc.)   |
| `--apps-json PATH`   | Override apps JSON file path                   |
| `--output-dir PATH`  | Override output directory                      |
| `--workers N`        | Override number of concurrent workers          |
| `--output-format FMT`| Override output format (json/yaml)             |
| `--resume`           | Resume from previous run                       |
| `--no-resume`        | Force process all apps                         |
| `--force-reprocess`  | Clear state and reprocess everything           |

### Examples

```bash
# Use all defaults from config.yaml
python privLess.py

# Analyze Python apps
python privLess.py --language python --apps-json ../apps/python_apps.json

# Custom output directory
python privLess.py --output-dir /path/to/output

# Force full reprocess with 8 workers
python privLess.py --force-reprocess --workers 8

# Use a different config file
python privLess.py --config /path/to/my-config.yaml
```

## Output Structure

After running, the output directory will contain:

```
output/
  databases/                    # CodeQL databases (one per app)
    javascript/
      db_<app-name>/
  results/
    service_calls/              # Raw service call extraction CSVs
      javascript/
    resolved_resources/         # Resource resolution CSVs
      javascript/
    policies/                   # Generated IAM policies
      javascript/
        <app-name>_policy.yml
    stats/                      # Analysis statistics
      javascript-typescript/
        analysis_stats.jsonl
        analysis_stats-time.csv
        processing_state.json
  logs/                         # Per-module log files
    privless.log
    codeql.log
    extractor.log
    resolver.log
    policy_generator.log
```

## How It Works

1. **Database Creation** - CodeQL creates a database from the application source code.
2. **Service Call Extraction** - A CodeQL query identifies all AWS SDK service calls (e.g., `s3.putObject`, `dynamodb.getItem`).
3. **Resource Resolution** - A second CodeQL query performs data-flow analysis to resolve the resource parameters (bucket names, table names, etc.) passed to each service call.
4. **Value Post-Processing** - For JavaScript/TypeScript, truncated string values from CodeQL output are resolved by reading the original source files.
5. **Environment Variable Resolution** - Resource values referencing environment variables are resolved from the `serverless.yml` configuration.
6. **Policy Generation** - Service calls and resolved resources are mapped to IAM actions and ARNs to produce minimal per-function IAM policies.

## Project Structure

```
privLess/
  config.yaml                  # Configuration file
  requirements.txt             # Python dependencies
  README.md                    # This file
  data/
    iam_service_actions.json   # AWS service -> IAM action mapping
  queries/
    javascript-typescript/     # CodeQL queries for JS/TS
    python/                    # CodeQL queries for Python
    go/                        # CodeQL queries for Go
  src/
    privLess.py                # Main entry point and orchestrator
    privLess_extractor.py      # Service call extraction
    privLess_resolver.py       # Resource value resolution
    privLess_policyGenerator.py # IAM policy generation
    privLess_analyzer.py       # Post-analysis statistics aggregation
    utils/
      config.py                # Configuration loader
      log.py                   # Logging setup
      codeql_agent.py          # CodeQL CLI wrapper
      postprocess_truncated_values.py  # Source value extraction
  scripts/
    generate_apps_json.py      # Generates per-language app lists from dataset/
  case-study-app/              # Sample serverless app for testing
  dataset/                     # Collection of serverless apps for bulk analysis
```

## Logging

Each module writes to its own log file in `<output_dir>/logs/`. The log level and console output can be controlled via `config.yaml`:

- `privless.log` - Main orchestrator
- `codeql.log` - CodeQL database creation and query execution
- `extractor.log` - Service call extraction
- `resolver.log` - Resource resolution
- `policy_generator.log` - Policy generation

Set `logging.level` to `DEBUG` for verbose output during troubleshooting.

## License

See [LICENSE](LICENSE) for details.
