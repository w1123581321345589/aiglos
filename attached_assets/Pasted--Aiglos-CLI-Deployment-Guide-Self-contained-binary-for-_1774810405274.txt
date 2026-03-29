# Aiglos CLI — Deployment Guide

Self-contained binary for AI agent runtime security in DevSecOps pipelines.
No MCP client required. No Node, no Python on the target system.

-----

## Quick Start

```bash
# Download the binary
curl -L https://github.com/youorg/aiglos/releases/latest/download/aiglos-linux -o aiglos
chmod +x aiglos

# Verify it works
aiglos rules
aiglos govbench --suite ndaa-1513 --output-format json
```

-----

## Tools

### `aiglos scan`

Run threat detection against an agent session log.

```bash
# Scan a JSONL session log
aiglos scan log_path=./session.jsonl policy=federal severity_threshold=high

# Pipe a live session
cat live-session.jsonl | aiglos scan log_path=/dev/stdin
```

### `aiglos audit`

Verify a signed session artifact for compliance.

```bash
aiglos audit artifact_path=./session-artifact.json framework=ndaa-1513
```

### `aiglos govbench`

Run the GOVBENCH evaluation suite.

```bash
# Full suite
aiglos govbench suite=full output_format=json > results.json

# NDAA §1513 targeted suite
aiglos govbench suite=ndaa-1513 output_format=junit > govbench.xml

# SARIF (for GitHub Advanced Security upload)
aiglos govbench suite=full output_format=sarif > govbench.sarif
```

### `aiglos rules`

Inspect active detection rules.

```bash
aiglos rules
aiglos rules filter_family=T10
aiglos rules filter_severity=critical
```

### `aiglos assert`

CI gate — exits non-zero on violations. Designed as a pipeline final step.

```bash
# Block on any high or critical violations
aiglos assert input_path=scan-result.json severity=high

# Enforce NDAA §1513 compliance
aiglos assert input_path=artifact.json framework=ndaa-1513 severity=critical

# Allow up to 2 medium violations
aiglos assert input_path=scan-result.json severity=medium max_violations=2
```

Exit codes: `0` = pass, `1` = violations exceed gate, `2` = error.

-----

## GitHub Actions Integration

```yaml
- name: Run GOVBENCH
  run: |
    aiglos govbench \
      suite=ndaa-1513 \
      output_format=junit > govbench.xml

- name: Assert security gate
  run: aiglos assert input_path=govbench.xml severity=high framework=ndaa-1513

- name: Upload results
  uses: actions/upload-artifact@v4
  with:
    name: govbench
    path: govbench.xml
```

-----

## Jenkins Integration

```groovy
stage('Aiglos Security Gate') {
    steps {
        sh '''
            aiglos govbench suite=ndaa-1513 output_format=json > govbench.json
            aiglos assert input_path=govbench.json severity=high framework=ndaa-1513
        '''
    }
    post {
        always {
            archiveArtifacts artifacts: 'govbench.json'
        }
    }
}
```

-----

## Environment Variables

|Variable            |Default  |Description                                       |
|--------------------|---------|--------------------------------------------------|
|`AIGLOS_LICENSE_KEY`|(none)   |Enterprise license key. MIT rules work without it.|
|`AIGLOS_POLICY`     |`default`|Policy profile: `default`, `federal`, `strict`    |
|`AIGLOS_LOG_LEVEL`  |`WARNING`|Log verbosity                                     |

-----

## Output Formats

All tools accept `--output json` for machine-readable output. The `govbench`
tool additionally supports `junit`, `sarif`, and `text`.

SARIF output integrates directly with GitHub Advanced Security:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: govbench.sarif
```

-----

## Rebuilding from Source

The binary embeds MCPorter metadata for reproducible regeneration:

```bash
# Inspect embedded metadata
npx mcporter inspect-cli dist/aiglos.js

# Rebuild with latest mcporter
npx mcporter generate-cli --from dist/aiglos.js
```

Or rebuild from scratch:

```bash
./scripts/build_cli.sh
```

-----

## NDAA §1513 Compliance

The `ndaa-1513` suite tests the eight threat families most directly cited in
the NDAA §1513 AI agent governance requirements. A score of 90% or higher on
this suite, combined with valid session artifact signing, satisfies the
attestation requirement for most procurement contexts.

Contact Aiglos for a formal compliance letter for DoD procurement packages.