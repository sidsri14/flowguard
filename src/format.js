/** Output formatters: human, JSON, SARIF 2.1.0. */
const LEVEL = { HIGH: "error", MEDIUM: "warning", LOW: "note", INFO: "note" };

export function formatHuman(report) {
  const lines = [];
  lines.push(`flowguard v${report.tool.version} — GitHub Actions workflow security scan`);
  lines.push(`Scanned ${report.scannedFiles} file(s).`);
  lines.push("");
  if (report.errors.length) {
    lines.push("Read errors:");
    for (const e of report.errors) lines.push(`  ! ${e.file}: ${e.error}`);
    lines.push("");
  }
  if (!report.findings.length) {
    lines.push("No findings.");
    return lines.join("\n");
  }
  lines.push(`Findings: ${report.counts.HIGH} high, ${report.counts.MEDIUM} medium, ${report.counts.LOW} low, ${report.counts.INFO} info`);
  lines.push("");
  let last = null;
  for (const f of report.findings) {
    if (f.file !== last) {
      lines.push(`  ${f.file}`);
      last = f.file;
    }
    lines.push(`  [${f.severity.padEnd(6)}] ${f.ruleId}  ${f.field}  (line ${f.startLine})`);
    lines.push(`      ${f.message}`);
    lines.push(`      fix: ${f.remediation}`);
  }
  return lines.join("\n");
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

export function formatSarif(report) {
  const used = [...new Set(report.findings.map((f) => f.ruleId))].sort();
  const meta = new Map();
  for (const f of report.findings) {
    if (!meta.has(f.ruleId)) {
      meta.set(f.ruleId, {
        id: f.ruleId,
        name: f.title.replace(/[^A-Za-z0-9]/g, ""),
        shortDescription: { text: f.title },
        fullDescription: { text: f.rationale },
        defaultConfiguration: { level: LEVEL[f.severity] || "warning" },
        help: { text: f.remediation },
        properties: { tags: ["security", "github-actions", "static-analysis"] }
      });
    }
  }
  const results = report.findings.map((f) => ({
    ruleId: f.ruleId,
    level: LEVEL[f.severity] || "warning",
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file.replace(/\\/g, "/") },
          region: { startLine: f.startLine, startColumn: f.startColumn }
        }
      }
    ],
    properties: { field: f.field, severity: f.severity }
  }));
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: report.tool.name,
              version: report.tool.version,
              informationUri: "https://github.com/sidsri14/flowguard",
              rules: used.map((id) => meta.get(id)).filter(Boolean)
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}
