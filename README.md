# flowguard

> Line-based static security linter for GitHub Actions workflows.

`flowguard` scans GitHub Actions workflow YAML and flags common CI/CD security mistakes: unpinned actions, `pull_request_target` pwn-requests, untrusted event data interpolated into scripts, `write-all` permissions, hardcoded credentials, remote-script-to-shell, and checkout token persistence. Zero runtime dependencies, Node 20+, SARIF output.

## Why

Workflows run with powerful tokens on every push and PR. Common, checkable mistakes include:

- `uses: owner/repo@v4` — a mutable tag that can change after review (pin to a commit SHA)
- `pull_request_target` checking out the PR's ref — attacker code with base-repo secrets
- `run: echo "${{ github.event.issue.title }}"` — shell injection via untrusted event text
- `permissions: write-all` — far more token scope than needed
- literal credentials in `env:`
- `curl … | bash` — executing unreviewed remote content
- `actions/checkout` retaining the token in git config for later steps

## Scope and non-claims

`flowguard` is a **line-based heuristic scanner**, not a YAML parser or a semantic analyzer. It:

- reads text line-by-line and matches documented patterns; it does not build an AST;
- may produce false positives (e.g. a `PASSWORD:` key holding a non-secret reference) and false negatives (obfuscated or multi-line constructs);
- does not execute workflows, contact GitHub, or read repository secrets;
- is not a substitute for a full workflow review, least-privilege design, or a dedicated tool like `zizmor`.

A clean scan means "none of these seven patterns were found," not "this workflow is secure."

## Install

```bash
npm install -g github:sidsri14/flowguard
# or, from a checkout:
node bin/flowguard.js scan .github/workflows
```

> npm registry publishing requires a maintainer login and is not set up. The GitHub install path above is the supported method today.

## Usage

```bash
flowguard scan .github/workflows
flowguard scan . --format sarif > flowguard.sarif
flowguard scan .github/workflows --format json --fail-on medium
flowguard rules
flowguard --version
```

### Options

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format <human\|json\|sarif>` | `human` | Output format |
| `--fail-on <high\|medium\|low>` | `high` | Minimum severity that sets exit code `1` |
| `--quiet` | off | Suppress human stdout |

### Exit codes

`0` = no findings at/above threshold and no read errors; `1` = findings at/above threshold; `2` = usage error or read errors without findings.

## Rules

| ID | Severity | Detects |
|---|---|---|
| `FG001` | HIGH | Action not pinned to a full commit SHA |
| `FG002` | HIGH | `pull_request_target` checking out a PR-controlled ref |
| `FG003` | HIGH | Untrusted `github.event.*` text interpolated into `run:` |
| `FG004` | MEDIUM | `permissions: write-all` |
| `FG005` | HIGH | Hardcoded credential in `env:` (value masked in output) |
| `FG006` | MEDIUM | `curl`/`wget` piped directly to a shell |
| `FG007` | LOW | `actions/checkout` without `persist-credentials: false` |

## Development

```bash
npm test
```

Uses Node's built-in `node:test` runner — no dev dependencies.

## License

MIT © 2026 Siddharth Srivastava
