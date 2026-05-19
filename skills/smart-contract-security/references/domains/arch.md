# S1: Architecture and Threat Modeling

**Control Objective:** Establish a secure foundation through sound architectural design, safe upgrade patterns, and systematic threat analysis.

---

## S1.1 Security Architecture

### S1.1.A Modular Design and Separation of Concerns

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S1.1.A1 | Verify that smart contracts are designed with a modular architecture to isolate components and limit the impact of vulnerabilities. | | ✓ | ✓ |
| S1.1.A2 | Ensure that each contract has a clearly defined responsibility, avoiding the mixing of unrelated functionality. | | ✓ | ✓ |
| S1.1.A3 | Check that contracts minimize the attack surface by exposing only necessary functions and data. | | ✓ | ✓ |
| S1.1.A4 | Verify that upgradeable patterns are implemented securely to prevent unauthorized changes and preserve contract state integrity. | | ✓ | ✓ |
| S1.1.A5 | Ensure that the contract's architecture supports threat modeling and systematic security assessment. | | ✓ | ✓ |

**How to Check:**
- Code Review: Verify each contract has one clear purpose. Look for mixed concerns (e.g., business logic + token logic in one contract).
- Check that `public`/`external` functions are minimized — only expose what callers need.
- Review proxy pattern implementation (if any) — see S1.2.

---

## S1.2 Upgradeable Patterns

### S1.2.A Secure Proxy Implementation

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S1.2.A1 | Verify that the proxy admin account is protected with multi-factor or multi-signature authorization. | | ✓ | ✓ |
| S1.2.A2 | Ensure that the UUPS (Universal Upgradeable Proxy Standard) implementation includes upgrade authorization checks in the logic contract. | | ✓ | ✓ |
| S1.2.A3 | Check that the proxy pattern does not introduce storage slot collisions between the proxy and implementation contracts. | | ✓ | ✓ |
| S1.2.A4 | Verify that initializer functions in upgradeable contracts are properly protected against being called multiple times. | | ✓ | ✓ |
| S1.2.A5 | Ensure that the upgrade authorization process follows a secure and auditable workflow, preventing unauthorized upgrades. | | ✓ | ✓ |

**Vulnerable Pattern — Storage Collision:**
```solidity
// Proxy stores admin at slot 0
contract Proxy {
    address public admin;  // slot 0
    address public implementation;  // slot 1
}
// Implementation ALSO uses slot 0 → collision
contract Impl {
    address public owner;  // slot 0 — COLLIDES with proxy.admin
}
```

**Fixed Pattern — EIP-1967 Storage Slots:**
```solidity
// Use pseudo-random storage slots to avoid collisions
bytes32 constant IMPLEMENTATION_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
bytes32 constant ADMIN_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
```

**UUPS Authorization Check:**
```solidity
// VULNERABLE — no auth on upgrade
function upgradeTo(address newImpl) public {
    _upgradeTo(newImpl);
}

// FIXED — only authorized caller can upgrade
function upgradeTo(address newImpl) public onlyOwner {
    _authorizeUpgrade(newImpl);
    _upgradeTo(newImpl);
}
```

**Initializer Protection:**
```solidity
// VULNERABLE — can be called multiple times
function initialize(address _owner) public {
    owner = _owner;
}

// FIXED — using OpenZeppelin Initializable
function initialize(address _owner) public initializer {
    owner = _owner;
}
```

**How to Check:**
- Code Review: Search for storage layout in both proxy and implementation; verify no slot overlap.
- Check `initialize()` is guarded with `initializer` modifier.
- Verify upgrade function checks `msg.sender == owner` or uses `onlyRole(UPGRADER_ROLE)`.
- Static Analysis: Slither detector `uninitialized-local` and `suicidal` flags are relevant.

---

## S1.3 Threat Modeling

### S1.3.A Systematic Threat Analysis

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S1.3.A1 | Verify that a threat model has been documented for the smart contract system, identifying potential attack vectors and mitigations. | | ✓ | ✓ |
| S1.3.A2 | Ensure that the threat model includes data flow diagrams that show how sensitive data moves through the system. | | | ✓ |
| S1.3.A3 | Check that trust boundaries are clearly defined in the threat model, separating trusted and untrusted components. | | ✓ | ✓ |
| S1.3.A4 | Verify that the threat model has been used to identify and address potential vulnerabilities in the contract design. | | ✓ | ✓ |
| S1.3.A5 | Ensure that the threat model is updated when significant changes are made to the contract architecture. | | | ✓ |

**How to Check:**
- Documentation Review: Verify threat model document exists and covers all external interactions (user calls, oracle integrations, admin actions).
- Verify data flow diagrams for sensitive operations (fund transfers, permission changes, upgrades).
- Check that trust boundaries are documented: which addresses are trusted? Which external contracts are assumed honest?
