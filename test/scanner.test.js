import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan, scanFile, expandInputs } from "../src/scanner.js";
import { RULES } from "../src/rules.js";
import { formatHuman, formatJson, formatSarif } from "../src/format.js";
import { run, EXIT } from "../src/cli.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (n) => path.join(here, "fixtures", n);

test("RULES has 9 unique documented rules", () => {
  assert.equal(RULES.length, 9);
  assert.equal(new Set(RULES.map((r) => r.id)).size, 9);
  for (const r of RULES) {
    assert.match(r.id, /^FG\d{3}$/);
    assert.ok(["HIGH", "MEDIUM", "LOW"].includes(r.severity));
    assert.ok(r.rationale && r.remediation);
  }
});

test("bad workflow triggers every rule", () => {
  const res = scanFile(fixture("bad-workflow.yml"));
  assert.equal(res.error, null);
  const ids = new Set(res.findings.map((f) => f.ruleId));
  for (const id of ["FG001", "FG002", "FG003", "FG004", "FG005", "FG006", "FG007"]) {
    assert.ok(ids.has(id), `expected ${id}`);
  }
  assert.ok(res.findings.every((f) => f.startLine >= 1));
});

test("good workflow is clean", () => {
  const res = scanFile(fixture("good-workflow.yml"));
  assert.equal(res.error, null);
  assert.deepEqual(res.findings, []);
});

test("FG005 masks credential values", () => {
  const res = scanFile(fixture("bad-workflow.yml"));
  const fg005 = res.findings.find((f) => f.ruleId === "FG005");
  assert.equal(fg005.value, "***masked***");
  assert.ok(!fg005.message.includes("literalpassword123"));
});

test("directory expansion finds YAML files", () => {
  const files = expandInputs([path.join(here, "fixtures")]);
  assert.ok(files.length >= 2);
  assert.ok(files.every((f) => f.endsWith(".yml")));
});

test("FG008 flags self-hosted runners on pull_request workflows", () => {
  const content = `
name: Untrusted PR
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo test
`;
  const f = path.join(here, ".tmp-self-hosted.yml");
  fs.writeFileSync(f, content);
  try {
    const ids = scanFile(f).findings.map((x) => x.ruleId);
    assert.ok(ids.includes("FG008"), "should flag self-hosted runner on PR");
  } finally {
    fs.unlinkSync(f);
  }
});

test("FG009 flags missing top-level permissions block", () => {
  const content = `
name: Missing permissions
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`;
  const f = path.join(here, ".tmp-no-perm.yml");
  fs.writeFileSync(f, content);
  try {
    const ids = scanFile(f).findings.map((x) => x.ruleId);
    assert.ok(ids.includes("FG009"), "should flag missing top-level permissions");
  } finally {
    fs.unlinkSync(f);
  }
});

test("missing file yields read error", () => {
  const res = scanFile(fixture("does-not-exist.yml"));
  assert.match(res.error, /Could not read file/);
});

test("aggregate report formatters valid", () => {
  const report = scan([fixture("bad-workflow.yml")]);
  assert.equal(report.tool.name, "flowguard");
  assert.ok(report.counts.HIGH >= 4);
  const json = JSON.parse(formatJson(report));
  assert.equal(json.tool.name, "flowguard");
  const sarif = JSON.parse(formatSarif(report));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.length > 0);
  assert.match(formatHuman(report), /flowguard v0\.1\.0/);
});

test("CLI exit codes", () => {
  assert.equal(run(["scan", fixture("bad-workflow.yml"), "--format", "json", "--quiet"]), EXIT.FINDINGS);
  assert.equal(run(["scan", fixture("good-workflow.yml"), "--format", "json", "--quiet"]), EXIT.OK);
  assert.equal(run(["scan"]), EXIT.ERROR);
  assert.equal(run(["bogus"]), EXIT.ERROR);
  assert.equal(run(["rules"]), EXIT.OK);
  assert.equal(run(["--version"]), EXIT.OK);
  assert.equal(run(["--help"]), EXIT.OK);
});
