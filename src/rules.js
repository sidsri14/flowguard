/** flowguard rules — line-based heuristics over GitHub Actions workflow YAML text. */

export const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

const UNTRUSTED_REF_RE = /github\.event\.(pull_request|issue|comment|check_run|discussion|inputs)/;
const UNTRUSTED_TEXT_RE = /github\.event\.(issue|pull_request|comment|discussion|check_run)[^}]*\.(title|body|name|login)/;
const SECRET_KEY_RE = /(password|passwd|secret|api[-_]?key|access[-_]?key|token|private[-_]?key|authorization)/i;
const SECRET_VALUE_RE = /(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

/** Each rule gets { file, lines, raw }. It returns findings without line metadata. */
export const RULES = [
  {
    id: "FG001",
    severity: "HIGH",
    title: "GitHub Action is not pinned to a full commit SHA",
    rationale:
      "An action referenced by branch or mutable tag can change after review. A full 40-hex commit SHA pins exactly what runs with your workflow's permissions.",
    remediation: "Pin to a full 40-character commit SHA: uses: owner/repo@<40-hex-sha> # v1.2.3",
    check({ lines }) {
      const out = [];
      lines.forEach((line, i) => {
        const m = line.match(/^\s*-?\s*uses:\s*([^\s#]+)@([^\s#]+)/);
        if (!m) return;
        const ref = m[2];
        if (/^[0-9a-fA-F]{40}$/.test(ref)) return;
        if (/^[0-9a-fA-F]{7,39}$/.test(ref)) return; // short SHA — still a commit
        if (/^(docker:|\.{1,2}\/)/.test(m[1])) return;
        out.push({ line: i + 1, field: "uses", value: ref, message: `Action '${m[1]}' uses mutable ref '${ref}', not a pinned commit SHA` });
      });
      return out;
    }
  },
  {
    id: "FG002",
    severity: "HIGH",
    title: "pull_request_target workflow checks out untrusted PR code",
    rationale:
      "pull_request_target runs in the base repository context with elevated secrets. Checking out the PR's ref executes attacker-controlled code with those privileges (a 'pwn request').",
    remediation: "Avoid running PR code under pull_request_target; use pull_request with least-privilege permissions, or never execute checked-out PR code in the privileged job.",
    check({ lines, raw }) {
      if (!/pull_request_target/.test(raw)) return [];
      const out = [];
      lines.forEach((line, i) => {
        if (!/uses:\s*actions\/checkout/.test(line)) return;
        // Look at the following few lines for a PR-controlled ref
        const window = lines.slice(i, i + 6).join("\n");
        if (UNTRUSTED_REF_RE.test(window)) {
          out.push({ line: i + 1, field: "checkout.ref", value: "untrusted-ref", message: "pull_request_target workflow checks out a PR-controlled ref" });
        }
      });
      return out;
    }
  },
  {
    id: "FG003",
    severity: "HIGH",
    title: "Untrusted event data interpolated into a run: script",
    rationale:
      "Values like github.event.issue.title or pull_request.body can contain shell metacharacters. Interpolating them directly into run: enables script injection.",
    remediation: "Pass untrusted data through env: and reference it as \"$VAR\" instead of interpolating ${{ ... }} into the shell.",
    check({ lines }) {
      const out = [];
      lines.forEach((line, i) => {
        if (/^\s*(run|working-directory):/.test(line) && UNTRUSTED_TEXT_RE.test(line)) {
          out.push({ line: i + 1, field: "run", value: "event-interpolation", message: "Untrusted github.event text interpolated into a run: script" });
        }
      });
      return out;
    }
  },
  {
    id: "FG004",
    severity: "MEDIUM",
    title: "Workflow grants write-all permissions",
    rationale:
      "permissions: write-all grants every GITHUB_TOKEN scope, far beyond what most workflows need. A compromised step can then modify issues, code, and releases.",
    remediation: "Use permissions: contents: read (or the minimum set) and elevate only the specific job that needs more.",
    check({ lines }) {
      const out = [];
      lines.forEach((line, i) => {
        if (/^\s*permissions:\s*write-all\s*$/.test(line)) {
          out.push({ line: i + 1, field: "permissions", value: "write-all", message: "Workflow uses permissions: write-all" });
        }
      });
      return out;
    }
  },
  {
    id: "FG005",
    severity: "HIGH",
    title: "Hardcoded credential in env block",
    rationale:
      "Literal credentials in a workflow are committed to source control and exposed to every step in the job.",
    remediation: "Use repository/organization secrets via ${{ secrets.NAME }} and rotate any credential that was committed.",
    check({ lines }) {
      const out = [];
      lines.forEach((line, i) => {
        const m = line.match(/^\s+([A-Za-z0-9_]+):\s*(.+?)\s*$/);
        if (!m) return;
        const [, key, value] = m;
        const isSecretish = SECRET_KEY_RE.test(key);
        const literalLooksSecret = SECRET_VALUE_RE.test(value);
        const isRef = value.includes("${{") || value.startsWith("$");
        if ((isSecretish || literalLooksSecret) && !isRef && value !== '""' && value !== "''") {
          out.push({ line: i + 1, field: `env.${key}`, value: "***masked***", message: `Possible hardcoded credential in env key '${key}' (value masked)` });
        }
      });
      return out;
    }
  },
  {
    id: "FG006",
    severity: "MEDIUM",
    title: "Remote script piped directly to a shell",
    rationale:
      "curl ... | bash executes whatever the remote server returns at run time, bypassing code review and pinning.",
    remediation: "Fetch, verify a checksum, then execute a reviewed local copy, or vendor the script into the repository.",
    check({ lines }) {
      const out = [];
      lines.forEach((line, i) => {
        if (/(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh\b/.test(line)) {
          out.push({ line: i + 1, field: "run", value: "pipe-to-shell", message: "Remote content piped directly to a shell" });
        }
      });
      return out;
    }
  },
  {
    id: "FG007",
    severity: "LOW",
    title: "actions/checkout without persisted credentials disabled",
    rationale:
      "By default actions/checkout stores the token in the local git config, making it readable by later steps in the same job.",
    remediation: "Set persist-credentials: false on the checkout step unless a later step genuinely needs the token.",
    check({ lines }) {
      const out = [];
      lines.forEach((line, i) => {
        if (!/uses:\s*actions\/checkout/.test(line)) return;
        const window = lines.slice(i, i + 6).join("\n");
        if (!/persist-credentials\s*:/.test(window)) {
          out.push({ line: i + 1, field: "checkout", value: "default", message: "actions/checkout does not set persist-credentials: false" });
        }
      });
      return out;
    }
  },
  {
    id: "FG008",
    severity: "HIGH",
    title: "Self-hosted runner used on pull_request or untrusted event",
    rationale:
      "Running untrusted pull requests on self-hosted runners exposes internal network infrastructure, host secrets, and container daemons to arbitrary code execution.",
    remediation: "Use GitHub-hosted runners (ubuntu-latest) for pull requests from untrusted forks or require an environment gate.",
    check({ lines, raw }) {
      if (!/(pull_request|pull_request_target|issues|issue_comment)/.test(raw)) return [];
      const out = [];
      lines.forEach((line, i) => {
        if (/runs-on:\s*(\[.*self-hosted.*\]|self-hosted)/i.test(line)) {
          out.push({ line: i + 1, field: "runs-on", value: "self-hosted", message: "Self-hosted runner used on untrusted PR or issue event" });
        }
      });
      return out;
    }
  },
  {
    id: "FG009",
    severity: "MEDIUM",
    title: "Workflow missing explicit top-level permissions block",
    rationale:
      "A workflow without a top-level permissions: block inherits the repository's default GITHUB_TOKEN permissions, which may grant write access to issues, checks, or contents.",
    remediation: "Define an explicit top-level 'permissions: contents: read' block to enforce least privilege.",
    check({ lines, raw }) {
      if (!/^\s*permissions\s*:/m.test(raw)) {
        return [{ line: 1, field: "permissions", value: "missing", message: "Workflow lacks an explicit top-level permissions block" }];
      }
      return [];
    }
  }
];
