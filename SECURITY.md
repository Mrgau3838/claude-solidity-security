# Security Policy

## Scope

This repository contains a Claude Code skill for smart contract security auditing. The scope of this policy covers:

- Incorrect or misleading security guidance in domain reference files
- Bugs in `parse-findings.py` that produce wrong SCSVS mappings
- Shell injection vulnerabilities in `slither-scan.sh`
- Any content that could cause harm if followed as security advice

## Reporting a Vulnerability

**Do not open a public GitHub issue for security findings.**

Report vulnerabilities by emailing: **demeter_financial@proton.me**

Please include:
- A clear description of the issue
- The affected file(s) and line numbers
- Potential impact
- A suggested fix if available

## Response Timeline

| Step | Timeline |
|------|----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Within 30 days for confirmed issues |
| Public disclosure | Coordinated with reporter |

## Out of Scope

- Vulnerabilities in third-party tools (Slither, Mythril, Foundry) — report these to their respective projects
- Findings in smart contracts audited *using* this skill — those are the user's responsibility

---

*Demeter Financial — © 2025*
