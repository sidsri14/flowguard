# GitHub Actions Security Review — proposed paid offer

**Status: PROPOSED. Not income. No payment received. Requires explicit approval before any external send.**

Ties the `flowguard` OSS tool to a fixed-scope paid service. Companion to the `mcpguard` and `toolshield`
offers — different input (GitHub Actions workflow YAML) and threat class (CI/CD supply chain).

## Live proof

- Source: https://github.com/sidsri14/flowguard (CI green on Node 20/22/24)
- Landing: https://sidsri14.github.io/flowguard/
- Sample review report (real scan of a synthetic fixture): https://sidsri14.github.io/flowguard/sample-report.html
- Tests: `npm test` — 8/8 passing, zero runtime dependencies

## Service — GitHub Actions Security Review

1. Run `flowguard` over the supplied workflow files.
2. Written report: rule ID, severity, line, rationale, concrete fix.
3. Corrected example workflow (SHA-pinned actions, least-privilege permissions, env-safe scripts).
4. Optional SARIF for GitHub code scanning.
5. One recheck after fixes.

### Out of scope

No workflow execution, no GitHub API access, no reading of the customer's secrets or repositories, no semantic
YAML analysis, no guarantee of "fully secure". The report covers the seven documented line-based rules only.
No tax/legal/compliance advice.

### Proposed pricing (NOT received, NOT agreed)

| Tier | Scope | Proposed price |
|---|---|---|
| Single review | Up to 5 workflow files | USD $150 |
| Team review | Up to 20 workflow files + SARIF + CI guidance | USD $350 |

### Payout boundary

Bank transfer or PayPal only (`sidsri1302@gmail.com`). No crypto/wallet/voucher/escrow funding, no spending,
no platform fees, no tax attestation by the assistant.

### Truthful seller qualification (verbatim or not at all)

> I'm Siddharth, an independent AI-assisted developer based in Lucknow, India. I built `flowguard`, an
> open-source, zero-dependency line-based security linter for GitHub Actions workflows with 7 documented
> rules and 8 passing tests. I offer a fixed-scope static workflow review — no workflow execution, no
> repository or secret access. I'll show source and test results before you pay.

Do not claim professional security experience, certifications, production deployments, named customers, or
unverifiable vulnerability counts.

## Where to offer

Only where a real buyer needs a workflow review. No unsolicited mass email, no duplicate sends, no Fiverr post
without a real on-platform order. Approval gate + daily first-contact cap apply.
