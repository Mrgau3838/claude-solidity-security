---
name: smart-contract-security
description: Use when auditing smart contracts for security vulnerabilities, verifying OWASP SCSVS compliance, or reviewing Solidity code for security issues. Covers all 11 SCSVS domains (S1–S11) with SCSTG testing methodology, static analysis tool integration (Slither, Mythril, Foundry), and dual-mode workflows for formal audits and quick inline reviews.
---

# Smart Contract Security

Dual-mode security skill for Solidity smart contracts, grounded in the OWASP Smart Contract Security Verification Standard (SCSVS v0.0.1) and Smart Contract Security Testing Guide (SCSTG v0.0.1).

## Mode Detection

Detect the user's intent from context:

| Signal | Mode |
|--------|------|
| "audit", "full review", "SCSVS report", "formal assessment" | **AUDIT** — full pipeline |
| "check this", "review", "is this safe?", "quick look", specific vuln question | **DEV** — inline review |
| Paste of a contract without instructions | Ask: "Quick security check or full audit?" |

## Router — What to Read

| Task | Reference |
|------|-----------|
| Run a full formal audit | `references/audit-workflow.md` |
| Quick inline code review / fix | `references/dev-workflow.md` |
| Identify contract type and risk profile | `references/taxonomy.md` |
| S1 Architecture & Threat Modeling | `references/domains/arch.md` |
| S2 Policies & Code Management | `references/domains/code.md` |
| S3 Business Logic & Economic Security | `references/domains/gov.md` |
| S4 Access Control | `references/domains/auth.md` |
| S5 Secure Interactions (Contract-to-Contract) | `references/domains/comm.md` |
| S6 Cryptographic Practices | `references/domains/crypto.md` |
| S7 Arithmetic & Logic Security | `references/domains/arith.md` |
| S8 Denial of Service (DoS) | `references/domains/dos.md` |
| S9 Blockchain Data & State Management | `references/domains/state.md` |
| S10 Gas Usage, Efficiency & Limitations | `references/domains/gas.md` |
| S11 Component-Specific Security | `references/domains/comp.md` |

## Quick Capability Overview

**Static Analysis:**
- Run `scripts/slither-scan.sh <contract.sol>` to get JSON findings
- Run `scripts/parse-findings.py <slither-output.json>` to map to SCSVS IDs

**Verification Levels:**
- **L1** Basic Security — all contracts
- **L2** Moderate Security — DeFi protocols, contracts handling sensitive data
- **L3** High Assurance — mission-critical, large TVL, bridge/oracle infrastructure

**SCSVS Domains Summary:**
```
S1  ARCH   — Architecture, proxy patterns, threat modeling
S2  CODE   — Compiler, code quality, test coverage
S3  GOV    — Business logic, tokenomics, reentrancy
S4  AUTH   — RBAC, authorization, decentralized identity
S5  COMM   — External calls, oracles, cross-chain, bridges
S6  CRYPTO — Key management, signature verification, randomness
S7  ARITH  — Overflow/underflow, arithmetic integrity
S8  DOS    — Gas limits, resource exhaustion
S9  STATE  — State management, privacy, event logging, storage
S10 GAS    — Gas optimization, efficient design
S11 COMP   — Tokens (ERC20/721/1155), NFTs, vaults, staking, AMMs
```

## Tool Integration

| Tool | Purpose | Command |
|------|---------|---------|
| Slither | Static analysis (~80 detectors) | `scripts/slither-scan.sh` |
| Mythril | Symbolic execution, deep vuln detection | `myth analyze <file.sol>` |
| Foundry/Forge | Fuzz testing, unit tests | `forge test --fuzz-runs 10000` |
| Echidna | Property-based fuzzing | `echidna-test . --contract <Name>` |

## Key Patterns to Always Check

1. **Reentrancy** — CEI pattern + `nonReentrant` modifier (S3.3)
2. **tx.origin auth** — must use `msg.sender` (S4.2.A1)
3. **delegatecall safety** — storage layout collisions (S1.2.A3)
4. **Integer overflow** — explicit type casts, `unchecked{}` blocks (S7.1)
5. **Oracle manipulation** — flash loan attack vectors on price feeds (S7.2.A1)
6. **ERC20 approval race** — set to 0 before updating allowance (S11.1)
7. **Signature malleability** — use nonces, EIP-712, ECDSA.recover checks (S6.1.A2)
8. **Unbounded loops** — gas DoS via dynamic arrays (S8.1.A3)
