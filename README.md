# Bitwarden Password Audit

`bitwarden_password_audit.sh` is a local, offline Bash tool that analyzes a Bitwarden CSV export and produces a concise password health report.

The goal is practical visibility: a clean overview of reused and weak passwords so you can act quickly without exposing secrets.

## What This Script Is For

This script is intended to provide a good overview of password risk as a report.

It focuses on:
- password reuse
- weak password patterns
- prioritized action items
- safe password references (ID + masked key)

For stronger coverage, use this report together with Have I Been Pwned (HIBP) checks for breach exposure.

## Input Format

- Expected input: Bitwarden **CSV** export (not JSON)
- Uses the Bitwarden `name` column for item-name identification

## Output Style

The report is intentionally compact:
- `Snapshot` (high-level counts)
- `Priority Issues` (single actionable table)

Each row is keyed by password ID (`P001`, `P002`, etc.) so you can review without revealing password values.

## Requirements

- Bash 4+
- Standard CLI tools: `awk`, `sed`, `grep`, `sort`, `uniq`, `cut`, `wc`, `tr`, `mktemp`

## Quick Start

```bash
chmod +x bitwarden_password_audit.sh
./bitwarden_password_audit.sh --input bitwarden.csv
```

## Help

```bash
./bitwarden_password_audit.sh --help
# or
./bitwarden_password_audit.sh -h
```

## Important Options

- `--input FILE` Path to Bitwarden CSV (required)
- `--mask-mode hidden|quarter|full` Mask behavior
- `--weakness-sensitivity low|medium|high` Weakness threshold profile
- `--min-repetition N` Minimum reuse count to flag
- `--max-findings [N]` Limit table rows
  - default without flag: top 10
  - with no value (`--max-findings`): show all
  - `--max-findings=0`: show all
- `--list-items-for ID` List full item names for one password ID (example: `P003`)

## Usage Examples

```bash
./bitwarden_password_audit.sh --input bitwarden.csv
./bitwarden_password_audit.sh --input bitwarden.csv --mask-mode hidden
./bitwarden_password_audit.sh --input bitwarden.csv --mask-mode full --max-findings
./bitwarden_password_audit.sh --input=bitwarden.csv --max-findings=15
./bitwarden_password_audit.sh --input bitwarden.csv --list-items-for P003
```

## Security Notes

- Runs locally; no network calls.
- Temporary files are cleaned on exit.
- `hidden` mode avoids revealing password length in the table.
- `full` mode is for trusted local sessions only.

## Collaboration

If you want to improve this tool, useful contribution areas are:
- scoring model quality
- visualization/readability
- additional safe integrations (for example HIBP workflows)
- tests for more CSV edge cases

## Publish To GitHub

If you already have the repository initialized locally, you can use:

```bash
git remote add origin https://github.com/ersad03/bitwarden-password-audit.git
git branch -M main
git push -u origin main
```

Script name in this project remains:

```bash
bitwarden_password_audit.sh
```
# bitwarden-password-audit
