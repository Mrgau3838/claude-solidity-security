# claude-solidity-security

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![OWASP SCSVS](https://img.shields.io/badge/OWASP-SCSVS%20v0.0.1-blue)
![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-blueviolet)

A Claude Code skill for auditing Solidity smart contracts, built on the [OWASP Smart Contract Security Verification Standard (SCSVS v0.0.1)](https://owasp.org/www-project-smart-contract-security/) and the [Smart Contract Security Testing Guide (SCSTG v0.0.1)](https://owasp.org/www-project-smart-contract-security/).

---

## Installation

**1. Clone or download this repository:**
```bash
git clone <repo-url> ~/smart-contract-security-skill
# or place the folder anywhere you like
```

**2. Register the skill with Claude Code:**
```bash
python3 - <<'PY'
import json, datetime

settings_path = "/home/<you>/.claude/settings.json"
plugins_path  = "/home/<you>/.claude/plugins/installed_plugins.json"
skill_path    = "/path/to/smart-contract-security-skill"

with open(plugins_path) as f:
    installed = json.load(f)

now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
installed["plugins"]["smart-contract-security@local"] = [{
    "scope": "user",
    "installPath": skill_path,
    "version": "1.0.0",
    "installedAt": now,
    "lastUpdated": now,
    "gitCommitSha": "local"
}]
with open(plugins_path, "w") as f:
    json.dump(installed, f, indent=2)

with open(settings_path) as f:
    settings = json.load(f)
settings.setdefault("enabledPlugins", {})["smart-contract-security@local"] = True
with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)

print("Done.")
PY
```

**3. Install optional static analysis tools:**
```bash
pip install slither-analyzer        # primary static analyzer
pip install mythril                 # symbolic execution
brew install foundry                # or: curl -L https://foundry.paradigm.xyz | bash
```

**4. Restart Claude Code.** The skill is now available in every session.

---

## Usage

Invoke the skill at the start of a session:

```
/smart-contract-security
```

Then describe your task naturally — the skill auto-detects the appropriate mode.

---

## Two Modes

### Audit Mode
For formal security assessments. Triggered by keywords like *"audit"*, *"full review"*, *"SCSVS report"*.

Runs a full 6-phase pipeline:
1. Contract intake & classification (13 contract types)
2. Automated static analysis (Slither + Mythril + Foundry)
3. Domain-by-domain manual review (all 11 SCSVS domains)
4. Vulnerability scoring (Critical / High / Medium / Low)
5. Structured report generation with SCSVS compliance matrix
6. Remediation verification

### Dev Mode
For quick inline code review. Triggered by *"check this"*, *"is this safe?"*, pasting code.

Runs a top-10 instant triage and returns:
```
⚠️ [SEVERITY]  Issue title
SCSVS: S3.3.A4
Line:  142
Problem: State updated after external call
Fix:   <corrected code snippet>
```

---

## Coverage

All 11 SCSVS domains are covered, each with full requirement tables and SCSTG testing methodology (vulnerable code → fixed code → how to check):

| Domain | Code | Topics |
|--------|------|--------|
| Architecture & Threat Modeling | S1 | Proxy patterns, storage collisions, upgrade auth, threat modeling |
| Policies & Code Management | S2 | Compiler version, deprecated functions, NatSpec, test coverage |
| Business Logic & Economic Security | S3 | Reentrancy (CEI, modifier ordering), pull/push withdrawal, tokenomics |
| Access Control | S4 | RBAC, tx.origin, EIP-712, multi-sig, Merkle allowlists |
| Secure Interactions | S5 | External calls, oracle feeds, cross-chain messaging, bridges |
| Cryptographic Practices | S6 | ecrecover, signature malleability, Chainlink VRF, nonces |
| Arithmetic & Logic Security | S7 | Overflow/underflow, fixed-point, flash loan math, rounding direction |
| Denial of Service | S8 | Unbounded loops, gas griefing, blocking patterns, try/catch |
| Blockchain Data & State Management | S9 | ETH locking, storage corruption, ZK proofs, event logging |
| Gas Usage & Efficiency | S10 | Storage packing, calldata, L2 solutions, re-org confirmations |
| Component-Specific Security | S11 | ERC20/721/1155, NFTs, vaults, stETH rebasing, AMMs, Uniswap V4 |

---

## Static Analysis Scripts

```bash
# Run Slither and produce JSON output
bash scripts/slither-scan.sh ./contracts

# Map Slither findings to SCSVS requirement IDs
python3 scripts/parse-findings.py slither-output.json
```

`parse-findings.py` maps ~40 Slither detectors deterministically to SCSVS IDs, producing a reproducible compliance diff between audit rounds.

---

## File Structure

```
skills/smart-contract-security/
├── SKILL.md                        # Mode detection + routing
├── references/
│   ├── audit-workflow.md           # Formal audit pipeline
│   ├── dev-workflow.md             # Quick-check workflow + fix patterns
│   ├── taxonomy.md                 # 13 contract types + risk matrix
│   └── domains/
│       ├── arch.md   (S1)
│       ├── code.md   (S2)
│       ├── gov.md    (S3)
│       ├── auth.md   (S4)
│       ├── comm.md   (S5)
│       ├── crypto.md (S6)
│       ├── arith.md  (S7)
│       ├── dos.md    (S8)
│       ├── state.md  (S9)
│       ├── gas.md    (S10)
│       └── comp.md   (S11)
└── scripts/
    ├── slither-scan.sh
    └── parse-findings.py
```

---

## Standards Referenced

- **SCSVS v0.0.1** — Smart Contract Security Verification Standard (OWASP, 2024)
- **SCSTG v0.0.1** — Smart Contract Security Testing Guide (OWASP, 2024)
- **EIP-712** — Typed structured data hashing and signing
- **EIP-1967** — Standard proxy storage slots
- **ERC-4626** — Tokenized vault standard

---

## Contributing

Issues and PRs are welcome. For security-related findings in this repository itself, please follow the [responsible disclosure policy](SECURITY.md).

---

*Built by [**Demeter Financial**](https://github.com/demeter-financial) — © 2025 Demeter Financial. Released under the [MIT License](LICENSE).*
