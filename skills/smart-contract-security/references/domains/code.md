# S2: Policies and Code Management

**Control Objective:** Ensure smart contracts are developed with sound engineering practices — correct compiler configuration, clear code, and comprehensive test coverage.

---

## S2.1 Development Policies

### S2.1.A Compiler and Language Best Practices

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S2.1.A1 | Verify that the smart contract specifies an up-to-date Solidity compiler version to benefit from the latest security patches and features. | ✓ | ✓ | ✓ |
| S2.1.A2 | Ensure that a specific compiler version is used (not a floating pragma like `^0.8.0`) to prevent unexpected behavior from compiler updates. | ✓ | ✓ | ✓ |
| S2.1.A3 | Verify that deprecated functions and language features are not used, as they may be removed or have security implications. | ✓ | ✓ | ✓ |
| S2.1.A4 | Check that the contract uses the latest stable language features appropriately and avoids experimental features in production. | | ✓ | ✓ |
| S2.1.A5 | Ensure that the contract is well-documented with comments and NatSpec annotations to facilitate understanding and auditing. | | ✓ | ✓ |

**Vulnerable — Floating Pragma:**
```solidity
// VULNERABLE — compiled with any 0.8.x version
pragma solidity ^0.8.0;
```

**Fixed — Pinned Version:**
```solidity
// FIXED — exact version, predictable behavior
pragma solidity 0.8.20;
```

**Deprecated Functions to Avoid:**

| Deprecated | Replacement | Risk |
|-----------|-------------|------|
| `suicide()` | `selfdestruct()` | Removed |
| `sha3()` | `keccak256()` | Removed |
| `throw` | `revert()` | Removed |
| `callcode()` | `delegatecall()` | Removed |
| `var` keyword | explicit types | Removed |
| `block.difficulty` | `block.prevrandao` (post-Merge) | Semantic change |

**How to Check:**
- Code Review: Check `pragma solidity` line — should be exact version (e.g., `0.8.20`), not `^0.8.0` or `>=0.8.0`.
- Static Analysis: Slither detector `pragma` flags version issues.
- Search for deprecated functions: `grep -n "suicide\|sha3\|throw\|callcode" contracts/`.

---

## S2.2 Code Clarity

### S2.2.A Readability and Maintainability

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S2.2.A1 | Verify that the smart contract code is readable, well-structured, and easy to understand for auditors and developers. | | ✓ | ✓ |
| S2.2.A2 | Ensure that the codebase is modular, with well-defined contracts and libraries that are reusable and maintainable. | | ✓ | ✓ |
| S2.2.A3 | Check that naming conventions are consistent and descriptive, aiding in code comprehension. | | ✓ | ✓ |
| S2.2.A4 | Verify that NatSpec comments are used for all public and external functions to document their purpose, parameters, and return values. | | ✓ | ✓ |
| S2.2.A5 | Ensure that the code does not contain dead code, redundant operations, or unnecessary complexity that could obscure its logic. | | ✓ | ✓ |

**How to Check:**
- Code Review: Check all `public`/`external` functions for NatSpec (`@notice`, `@param`, `@return`).
- Look for dead code: unreachable branches, unused variables, disabled tests.
- Verify naming: state variables use `s_` prefix (or equivalent convention), events use past tense, etc.

---

## S2.3 Test Coverage

### S2.3.A Comprehensive Testing Strategy

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S2.3.A1 | Verify that the smart contract has comprehensive unit tests covering all critical functions and edge cases. | | ✓ | ✓ |
| S2.3.A2 | Ensure that fuzz testing or property-based testing is used to identify unexpected behaviors under varied inputs. | | | ✓ |
| S2.3.A3 | Check that integration tests are implemented to verify the correct interaction between contracts and external systems. | | ✓ | ✓ |
| S2.3.A4 | Verify that mutation testing or equivalent techniques are used to assess test quality and coverage effectiveness. | | | ✓ |
| S2.3.A5 | Ensure that automated test execution is integrated into the development workflow using CI/CD pipelines. | | ✓ | ✓ |

**How to Check — Foundry:**
```bash
# Run all tests
forge test -vvv

# Fuzz testing
forge test --fuzz-runs 10000

# Coverage report
forge coverage --report lcov

# Gas snapshot
forge snapshot
```

**How to Check — Hardhat:**
```bash
npx hardhat test
npx hardhat coverage
```

**Minimum Coverage Expectations:**
- L2: ≥80% statement coverage on critical paths
- L3: ≥95% with fuzz testing on arithmetic-heavy functions

**What to Look For:**
- Are edge cases tested? (zero amounts, max values, empty arrays)
- Are access control tests present? (unauthorized caller reverts)
- Are reentrancy scenarios tested?
- Is the test suite deterministic (no time-dependent tests without mocking)?
