# Formal Audit Workflow

Complete pipeline for professional smart contract security audits. Follow all phases in order.

---

## Phase 1 — Contract Intake & Classification

1. **Identify contract type** — read `taxonomy.md` and classify against the 13 types
2. **Determine scope** — list all Solidity files, interfaces, libraries, and external dependencies
3. **Select verification level** based on classification:
   - L1: Simple utility contracts, basic tokens
   - L2: DeFi protocols, contracts with user funds, sensitive logic
   - L3: Bridges, oracles, mission-critical infrastructure (>$10M TVL threshold)
4. **Document deployment context**: chain (mainnet/L2/sidechain), Solidity version, framework (Hardhat/Foundry), any prior audits

---

## Phase 2 — Static Analysis

Run tools automatically and collect JSON output before manual review:

```bash
# Slither (primary)
bash scripts/slither-scan.sh <contracts_dir>

# Map findings to SCSVS
python3 scripts/parse-findings.py slither-output.json

# Mythril (symbolic execution — per file)
myth analyze contracts/MyContract.sol --solv 0.8.x

# Foundry fuzz (if test suite present)
forge test --fuzz-runs 10000 -vvv
```

Triage all HIGH/MEDIUM findings before proceeding to manual review.

---

## Phase 3 — Domain-by-Domain Manual Review

Work through each domain in order. For each domain:
1. Load the domain reference file
2. Check every requirement at the applicable verification level (L1/L2/L3)
3. Mark: PASS | FAIL | N/A | INFO

### Domain Checklist

| Domain | File | Focus |
|--------|------|-------|
| S1 Architecture | `domains/arch.md` | Proxy pattern, upgrade mechanism, threat model |
| S2 Code Management | `domains/code.md` | Compiler version, deprecated functions, test coverage |
| S3 Business Logic | `domains/gov.md` | Reentrancy, pull/push, tokenomics, economic attacks |
| S4 Access Control | `domains/auth.md` | RBAC, tx.origin, multi-sig, EIP-712 |
| S5 Interactions | `domains/comm.md` | External calls, oracle trust, cross-chain, bridges |
| S6 Cryptography | `domains/crypto.md` | ecrecover, signature malleability, randomness |
| S7 Arithmetic | `domains/arith.md` | Overflow, fixed-point, precision, flash loan math |
| S8 DoS | `domains/dos.md` | Gas limits, unbounded loops, blocking patterns |
| S9 State | `domains/state.md` | Storage corruption, data privacy, event logging |
| S10 Gas | `domains/gas.md` | Optimization, L2 solutions, confirmation numbers |
| S11 Components | `domains/comp.md` | ERC20/721/1155, NFT, vaults, liquid staking, AMMs |

---

## Phase 4 — Vulnerability Scoring

For each finding, assign:

| Field | Values |
|-------|--------|
| **Severity** | Critical / High / Medium / Low / Informational |
| **SCSVS Ref** | e.g., `S3.3.A4`, `S7.1.A2` |
| **Impact** | Funds at risk / Access control bypass / DoS / Data corruption / Other |
| **Likelihood** | High / Medium / Low |
| **Exploitability** | Immediate / Requires conditions / Theoretical |

**Severity Matrix:**
- **Critical** — Direct fund loss, unprotected self-destruct, complete access bypass
- **High** — Reentrancy, integer overflow with funds, unauthorized admin actions
- **Medium** — Logic errors, improper access control, oracle manipulation
- **Low** — Informational findings, gas inefficiencies with no security impact
- **Informational** — Code quality, best practice deviations

---

## Phase 5 — Report Generation

Structure the audit report as follows:

```markdown
# Smart Contract Security Audit Report

## Executive Summary
- Contract(s) audited
- Scope and verification level
- Finding counts by severity
- Overall risk rating

## Methodology
- Tools used (Slither, Mythril, Foundry)
- Domains reviewed
- Verification level applied (L1/L2/L3)

## Findings

### [CRIT-01] <Title>
- **SCSVS Reference:** S3.3.A4
- **Severity:** Critical
- **Location:** `contracts/Vault.sol:142`
- **Description:** [Clear description of vulnerability]
- **Impact:** [What an attacker can do]
- **Proof of Concept:** [Code snippet or attack scenario]
- **Recommendation:** [Specific fix]
- **References:** [Link to SCSVS/SCSTG]

[Repeat for each finding]

## SCSVS Compliance Matrix
[Table of all requirements: PASS/FAIL/N/A per domain]

## Appendix
- Tool output summaries
- Slither findings mapped to SCSVS IDs
```

---

## Phase 6 — Remediation Verification

After fixes are applied:
1. Re-run static analysis tools on patched contracts
2. Verify each FAIL item has been addressed
3. Confirm no regressions introduced
4. Update compliance matrix
5. Issue final report with remediation status

---

## Audit Anti-Patterns to Avoid

- Do NOT skip domain-by-domain review just because static analysis found nothing
- Do NOT mark requirements N/A without documenting the reason
- Do NOT rely solely on automated tools — symbolic execution misses business logic flaws
- Do NOT audit without knowing the contract type (taxonomy determines which S11 subsections apply)
