# S4: Access Control

**Control Objective:** Ensure that only authorized parties can perform privileged operations, using sound RBAC patterns and cryptographic authentication.

---

## S4.1 Role-Based Access Control (RBAC)

### S4.1.A Role Management and Privilege Separation

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S4.1.A1 | Verify that role-based access control (RBAC) is implemented to manage permissions and responsibilities within the contract. | | ✓ | ✓ |
| S4.1.A2 | Ensure that role assignment and revocation processes are securely implemented to prevent unauthorized privilege escalation. | | ✓ | ✓ |
| S4.1.A3 | Check that the contract implements mechanisms to prevent unauthorized privilege escalation. | | ✓ | ✓ |
| S4.1.A4 | Verify that the principle of least privilege is applied, granting each role only the permissions necessary for its function. | | ✓ | ✓ |
| S4.1.A5 | Ensure that two-factor authentication or multi-signature schemes are used for critical administrative operations. | | | ✓ |
| S4.1.C1 | Verify that `msg.sender` is used instead of `tx.origin` for authorization. | | ✓ | ✓ |

**tx.origin Phishing Attack:**
```solidity
// VULNERABLE — tx.origin can be manipulated
// Attacker creates a malicious contract that the owner calls
// tx.origin == owner even inside the malicious contract
modifier onlyOwner() {
    require(tx.origin == owner, "Not owner");  // ← VULNERABLE
    _;
}

// FIXED — use msg.sender
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}
```

**Merkle Tree for Large Whitelists (S4.3.C1):**
```solidity
// Efficient allowlist using Merkle proofs instead of on-chain arrays
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

bytes32 public merkleRoot;

function claim(bytes32[] calldata proof) external {
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
    // proceed with claim
}
```

**How to Check:**
- Code Review: Search for `tx.origin` in all modifier and require conditions — replace with `msg.sender`.
- Verify OpenZeppelin `AccessControl` or equivalent is used for multi-role contracts.
- Check that `DEFAULT_ADMIN_ROLE` is protected and not left to `address(0)` or `msg.sender` in constructor without further restriction.
- Static Analysis: Slither detector `tx-origin`.

---

## S4.2 Authorization

### S4.2.A Secure Authorization Patterns

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S4.2.A1 | Verify that `msg.sender` is used (not `tx.origin`) for authorization checks. | | ✓ | ✓ |
| S4.2.A2 | Ensure that authorization checks are performed before any state changes or external calls. | | ✓ | ✓ |
| S4.2.A3 | Check that mechanisms exist to prevent unauthorized bypassing of access controls through alternative execution paths. | | ✓ | ✓ |
| S4.2.A4 | Verify that `delegatecall` targets are authorized and cannot be set by untrusted callers. | | ✓ | ✓ |

**Authorized delegatecall:**
```solidity
// VULNERABLE — untrusted target for delegatecall
function execute(address target, bytes calldata data) external {
    target.delegatecall(data);  // attacker can pass malicious contract
}

// FIXED — whitelist allowed targets
mapping(address => bool) public approvedTargets;

function execute(address target, bytes calldata data) external onlyOwner {
    require(approvedTargets[target], "Target not approved");
    (bool success, bytes memory result) = target.delegatecall(data);
    if (!success) {
        assembly { revert(add(result, 32), mload(result)) }
    }
}
```

---

## S4.3 Decentralized Identity and Signature Authentication

### S4.3.A Multi-Signature Authorization

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S4.3.A1 | Verify that multi-signature schemes require a minimum number of valid signatures from authorized parties before executing sensitive operations. | | ✓ | ✓ |
| S4.3.A2 | Ensure that multi-signature contracts are protected against replay attacks, ensuring each transaction is unique. | | ✓ | ✓ |

### S4.3.B Off-Chain Signatures with EIP-712

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S4.3.B1 | Check that off-chain signatures for on-chain operations use typed structured data hashing (EIP-712) to prevent signature reuse across contexts. | | ✓ | ✓ |
| S4.3.B2 | Verify that signatures include a domain separator to bind them to the specific contract and chain. | | ✓ | ✓ |

### S4.3.C Large-Scale Allowlists

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S4.3.C1 | Ensure that Merkle trees are used for verifying large sets of authorized addresses to minimize on-chain storage. | | ✓ | ✓ |

### S4.3.D Replay Protection

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S4.3.D1 | Verify that nonces or timestamps are included in signed messages to prevent replay attacks. | | ✓ | ✓ |

**EIP-712 Signature Pattern:**
```solidity
// CORRECT EIP-712 implementation
bytes32 constant DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("MyContract"),
    keccak256("1"),
    block.chainid,
    address(this)
));

bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
);

function verify(address owner, bytes calldata sig, ...) internal view returns (bool) {
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner], deadline));
    bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    address recovered = ECDSA.recover(hash, sig);
    return recovered == owner;
}
```

**How to Check:**
- Code Review: Verify `chainId` and `address(this)` are in the domain separator — prevents cross-chain and cross-contract replay.
- Check nonce is incremented per-use and never reusable.
- Verify `ecrecover()` return value is checked for `address(0)` (failed recovery returns zero address).
- Static Analysis: Slither detector `arbitrary-send-eth` can catch auth bypass scenarios.
