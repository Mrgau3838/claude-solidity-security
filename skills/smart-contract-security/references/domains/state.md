# S9: Blockchain Data and State Management

**Control Objective:** Establish practices for effective management of blockchain data and state to ensure security, efficiency, and integrity of contract interactions.

---

## S9.1 State Management

### S9.1.A Efficient and Secure State Handling

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.1.A1 | Ensure that payable functions in contracts handle all ETH passed in `msg.value` and provide a mechanism for withdrawal to avoid ETH being locked in the contract. | | ✓ | ✓ |
| S9.1.A2 | Verify that deleting a variable of a nested structure correctly resets all nested level fields to default values to avoid unexpected behavior. | | ✓ | ✓ |
| S9.1.A3 | Verify that storage structs and arrays with types shorter than 32 bytes are handled correctly, avoiding data corruption when encoded directly from storage using the experimental `ABIEncoderV2`. | | ✓ | ✓ |
| S9.1.A4 | Verify that storage arrays containing structs or other statically-sized arrays are properly read and encoded in external function calls to prevent data corruption. | | ✓ | ✓ |
| S9.1.A5 | Ensure that copying bytes arrays from memory or calldata to storage handles empty arrays correctly, avoiding data corruption when the target array's length is increased subsequently without storing new data. | | ✓ | ✓ |

### S9.1.B State Channels

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.1.B1 | Verify that global state updates are correctly handled when working with memory copies to ensure accurate state management. | | ✓ | ✓ |

**ETH Locking Prevention (S9.1.A1):**
```solidity
// VULNERABLE — ETH can be locked if no withdraw mechanism
contract EthLock {
    receive() external payable {}  // accepts ETH but can never send it out
}

// FIXED — always provide withdrawal mechanism for payable contracts
contract SecurePayable {
    address public owner;
    mapping(address => uint256) public deposits;

    receive() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "No deposit");
        deposits[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
```

**Nested Struct Delete (S9.1.A2):**
```solidity
struct Inner {
    uint256 value;
    address addr;
}

struct Outer {
    Inner inner;
    uint256 other;
}

mapping(uint256 => Outer) public data;

// VULNERABLE — incomplete delete may leave nested fields
// In older Solidity, deleting Outer may not zero all Inner fields
// SAFE in Solidity >=0.8.0 but verify explicitly for complex nesting
delete data[id];  // should reset all nested fields to defaults
// Always test delete behavior with nested structs
```

**Memory-to-Storage Copy (S9.1.B1):**
```solidity
// VULNERABLE — memory copy does NOT update storage
function updateValue(uint256 id, uint256 newValue) external {
    Struct memory item = storageMap[id];  // loads to memory
    item.value = newValue;                // modifies memory copy
    // storage NOT updated — item goes out of scope
}

// FIXED — use storage reference
function updateValue(uint256 id, uint256 newValue) external {
    Struct storage item = storageMap[id];  // storage reference
    item.value = newValue;                 // modifies storage directly
}
```

**How to Check:**
- Code Review: Every `memory` copy of a storage struct that is then modified — does it write back to storage?
- Check all `payable` functions for corresponding withdrawal mechanisms.
- Search for `delete` on nested structs — verify all nested fields reset correctly.
- Static Analysis: Slither detector `write-after-write` flags some state management issues.

---

## S9.2 Data Privacy

### S9.2.A Ensuring Sensitive Data is Secure

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.2.A1 | Ensure that private data marked in contracts is protected from unauthorized access through blockchain analysis. | | ✓ | ✓ |

### S9.2.B Zero-Knowledge Proofs

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.2.B1 | Verify that zero-knowledge proofs are implemented to ensure privacy without revealing any underlying data. | | ✓ | ✓ |
| S9.2.B2 | Validate the correctness of proof generation and verification processes to prevent any potential leaks or exploits. | | ✓ | ✓ |
| S9.2.B3 | Ensure that zero-knowledge proofs are integrated seamlessly with the blockchain to maintain performance and security. | | ✓ | ✓ |

### S9.2.C Private Transactions

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.2.C1 | Verify that private transaction mechanisms (e.g., zk-SNARKs, zk-STARKs) are correctly implemented to ensure confidentiality of transaction details. | | ✓ | ✓ |
| S9.2.C2 | Ensure that private transactions maintain the integrity and validity of the blockchain. | | ✓ | ✓ |

### S9.2.D Confidential Contracts

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.2.D1 | Verify that confidential contracts use cryptographic techniques to hide contract state and execution details from unauthorized parties. | | ✓ | ✓ |
| S9.2.D2 | Ensure that only parties with appropriate permissions can access data within confidential contracts. | | ✓ | ✓ |

**Private Storage Is Not Private:**
```solidity
// DANGEROUS MISCONCEPTION — `private` does NOT encrypt data
// All storage slots are publicly readable via eth_getStorageAt
contract DataPrivacy {
    mapping(address => uint256) private balances;  // ← NOT truly private

    // This event exposes balance on-chain in plaintext
    function logBalance() public {
        emit UserBalance(msg.sender, balances[msg.sender]);  // visible to all
    }
}

// For real privacy: hash sensitive data, use ZK proofs, or encrypt off-chain
// Store only hashes on-chain: mapping(address => bytes32) private hashedData;
```

**How to Check:**
- Code Review: Identify any `private` or `internal` state variables containing sensitive data (keys, balances, private info) — these are readable from the blockchain.
- Check event emissions — do they expose sensitive amounts or addresses in plaintext?
- For ZK implementations: verify circuit constraints match business logic exactly.

---

## S9.3 Event Logging

### S9.3.A Transparent and Secure Logging Practices

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.3.A1 | Verify that events are emitted properly, especially for critical changes to ensure traceability and transparency. | | ✓ | ✓ |
| S9.3.A2 | Verify that the contract's event logging correctly reflects critical changes to ensure transparency and traceability. | | ✓ | ✓ |

### S9.3.B Log Analysis

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.3.B1 | Implement tools and processes for analyzing event logs to detect anomalies or unauthorized changes. | | ✓ | ✓ |
| S9.3.B2 | Set up alerts for unusual patterns or discrepancies in logged events. | | ✓ | ✓ |

**Missing Events (S9.3.A1):**
```solidity
// VULNERABLE — state changes without events make auditing impossible
function setData(uint256 newData) public {
    data = newData;
    // No event emitted ← difficult to detect unauthorized changes
}

// FIXED — emit event on every critical state change
event DataUpdated(uint256 newData);

function setData(uint256 newData) public onlyOwner {
    data = newData;
    emit DataUpdated(newData);  // ← enables off-chain monitoring
}
```

**What Events Must Be Emitted:**
- All ownership/role transfers
- All fund movements (deposits, withdrawals, transfers)
- All parameter changes (fees, limits, addresses)
- All pause/unpause operations
- All upgrade operations (for proxies)

---

## S9.4 Decentralized Storage

### S9.4.A IPFS, Arweave

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S9.4.A1 | Ensure that data stored on decentralized platforms like IPFS or Arweave is encrypted and access-controlled. | | ✓ | ✓ |
| S9.4.A2 | Implement mechanisms for data redundancy and backup to ensure data availability. | | ✓ | ✓ |

**How to Check:**
- Code Review: Verify NFT metadata URIs point to IPFS/Arweave, not centralized servers (mutable → rug risk).
- Check that off-chain data referenced on-chain is content-addressed (IPFS CID) not location-addressed (URL).
- For NFT projects: verify metadata is pinned on IPFS and has redundant pinning services.
