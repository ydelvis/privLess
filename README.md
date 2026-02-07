# PrivLess

**Least-privilege IAM policy generator for serverless applications.**

PrivLess uses [CodeQL](https://codeql.github.com/) static analysis to extract the AWS permissions each serverless function actually uses and generates tightly-scoped IAM policies, enabling over-privilege analysis of serverless applications.

## Supported Languages

| Language              | Status    |
| --------------------- | --------- |
| JavaScript/TypeScript | Supported |
| Python                | Supported |
| Go                    | Supported |
| C#                    | Supported |

## Prerequisites

- **Python 3.8+**
- **CodeQL CLI** installed and available in your PATH (or set the path in `config.yaml`)
  - Install: https://github.com/github/codeql-cli-binaries/releases
  - After downloading, either add it to your PATH or set `codeql.executable` in `config.yaml`

## Installation

```bash
# Clone the repository
git clone <repo-url> privLess
cd privLess

# Install Python dependencies
pip install -r requirements.txt
```

## Configuration

All configurable settings live in `config.yaml` at the project root. CLI arguments override config values where applicable. Key settings:

| Setting              | Description                                             | Default        |
| -------------------- | ------------------------------------------------------- | -------------- |
| `codeql.executable`  | Path to CodeQL binary, or `"codeql"` to use system PATH | `"codeql"`     |
| `analysis.language`  | Language of the serverless apps                         | `"javascript"` |
| `analysis.apps_json` | JSON file with list of app paths                        | `"apps.json"`  |
| `analysis.workers`   | Parallel processing threads                             | `4`            |
| `analysis.resume`    | Resume from previous run                                | `true`         |
| `output.dir`         | Base output directory                                   | `"output"`     |
| `logging.level`      | Log verbosity                                           | `"INFO"`       |

## Repository Structure

```
privLess/
  config.yaml                    # All configurable settings
  requirements.txt               # Python dependencies
  data/                          # Reference data (IAM action mappings)
  queries/                       # CodeQL queries per language
  src/                           # Core PrivLess pipeline          [1]
  tools/                         # Standalone analysis tools       [2,3,4]
  analysis/                      # Jupyter notebooks for results   [5]
  scripts/                       # Helper scripts
  case-study-app/                # Sample serverless app for testing
  dataset/                       # Serverless apps for bulk analysis
  output/                        # All generated output (gitignored)
```

## Workflow

The components are designed to run in the following order:

### 1. Run the PrivLess pipeline (`src/`)

The core analysis engine. Uses CodeQL to extract AWS service calls from source code and generates tightly-scoped IAM policies based on actual code usage.

```bash
cd src
python privLess.py --language javascript --apps-json ../apps.json
```

See [src/README.md](src/README.md) for full CLI reference and examples.

**Output:** `output/results/` — per-app policies, service call CSVs, statistics

### 2. Run the Default Policy Analyzer (`tools/default_policy_analyzer/`)

Extracts the IAM policies developers originally declared in their `serverless.yml` files. Used to compare default privileges against the usage-based policies from step 1 and quantify over-privilege.

```bash
python tools/default_policy_analyzer/privLess_default_policy_analyzer.py \
  --language javascript --apps-json apps.json
```

See [tools/default_policy_analyzer/README.md](tools/default_policy_analyzer/README.md) for details.

**Output:** `output/results/default_policy_analysis/`

### 3. Run the Permission Classifier (`tools/permission_classifier/`)

Classifies declared AWS permissions into security impact categories (Reconnaissance, Data Exfiltration, Privilege Escalation, etc.).

```bash
python tools/permission_classifier/permission_classifier.py --apps-json apps.json
```

See [tools/permission_classifier/README.md](tools/permission_classifier/README.md) for details.

**Output:** `output/results/permission_classifications/`

### 4. Combine results across languages (`tools/combine_results.py`)

Merges per-language output files into single combined files for cross-language analysis.

```bash
python tools/combine_results.py
```

**Output:** Combined JSONL and CSV files in `output/results/`

### 5. Analyze results (`analysis/`)

Jupyter notebooks that load the combined results and produce figures and statistics.

See [analysis/README.md](analysis/README.md) for prerequisites and notebook descriptions.

## Output Structure

All output is written under `output/` (configurable via `config.yaml`):

```
output/
  databases/                          # CodeQL databases (one per app)
  results/
    service_calls/<language>/         # Extracted service call CSVs
    resolved_resources/<language>/    # Resource resolution CSVs
    policies/<language>/              # Generated IAM policies
    stats/<language>/                 # Per-language analysis statistics
      analysis_stats.jsonl
      analysis_stats-time.csv
    stats/
      combined_analysis_stats.jsonl   # Combined (all languages)
      combined_analysis_stats-time.csv
    default_policy_analysis/          # Default policy analyzer output
      combined_default_policy_stats.jsonl
    permission_classifications/       # Permission classifier output
      permission_classifications.csv
  logs/                               # Per-module log files
```

## Quick Start — Case Study App

A sample Node.js serverless app is included for testing:

```bash
echo '["case-study-app/aws-node-http-api-dynamodb-local"]' > apps.json
cd src
python privLess.py --language javascript --apps-json ../apps.json
```

## License

See [LICENSE](LICENSE) for details.
