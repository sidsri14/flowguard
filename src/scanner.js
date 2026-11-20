/** Core scanning: discover YAML workflow files, run line-based rules. */
import fs from "node:fs";
import path from "node:path";
import { RULES, SEVERITY_ORDER } from "./rules.js";

const WORKFLOW_EXT = new Set([".yml", ".yaml"]);

export function findWorkflowFiles(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (![".git", "node_modules", "dist", "build", "coverage"].includes(entry.name)) {
        findWorkflowFiles(path.join(dir, entry.name), out);
      }
    } else if (entry.isFile() && WORKFLOW_EXT.has(path.extname(entry.name).toLowerCase())) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

export function expandInputs(inputs) {
  const files = [];
  for (const input of inputs) {
    let stat;
    try {
      stat = fs.statSync(input);
    } catch {
      continue;
    }
    if (stat.isDirectory()) files.push(...findWorkflowFiles(input));
    else if (stat.isFile()) files.push(input);
  }
  return [...new Set(files)];
}

export function scanFile(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (err) {
    return { file, findings: [], error: `Could not read file: ${err.message}` };
  }
  const lines = raw.split(/\r?\n/);
  const findings = [];
  for (const rule of RULES) {
    let matches = [];
    try {
      matches = rule.check({ file, lines, raw }) || [];
    } catch (err) {
      matches = [{ line: 1, field: "(rule error)", value: "", message: `${rule.id} failed: ${err.message}` }];
    }
    for (const m of matches) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        rationale: rule.rationale,
        remediation: rule.remediation,
        file,
        field: m.field,
        value: m.value,
        message: m.message,
        startLine: m.line || 1,
        startColumn: 1
      });
    }
  }
  findings.sort((a, b) => {
    const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (s !== 0) return s;
    return a.startLine - b.startLine || a.ruleId.localeCompare(b.ruleId);
  });
  return { file, findings, error: null, isWorkflow: true };
}

export function scan(inputs) {
  const files = expandInputs(inputs);
  const results = files.map(scanFile);
  const findings = results.flatMap((r) => r.findings);
  const errors = results.filter((r) => r.error).map((r) => ({ file: r.file, error: r.error }));
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return {
    tool: { name: "flowguard", version: "0.1.0" },
    scannedFiles: files.length,
    findings,
    errors,
    counts
  };
}
