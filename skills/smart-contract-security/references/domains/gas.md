# S10: Gas Usage, Efficiency, and Limitations

**Control Objective:** Establish practices for optimizing gas usage and efficiency in smart contracts to minimize costs and enhance performance.

---

## S10.1 Optimizing Gas Usage

### S10.1.A Understanding Gas Costs and Limits

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S10.1.A1 | Implement best practices for optimizing gas consumption to ensure cost-effective and efficient contract execution. | | ✓ | ✓ |

### S10.1.B Gas Estimation Tools

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S10.1.B1 | Verify that transaction confirmation numbers are chosen appropriately to mitigate risks related to chain re-orgs and ensure reliable contract operation. | | ✓ | ✓ |

---

## S10.2 Efficient Contract Design

### S10.2.A Layer 2 Solutions

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S10.2.A1 | Explore and integrate Layer 2 scaling solutions (e.g., rollups, state channels) to improve transaction throughput and reduce gas costs. | | ✓ | ✓ |
| S10.2.A2 | Verify the security and reliability of Layer 2 solutions before integration. | | ✓ | ✓ |

---

## Testing Gas Usage

### Test 1: Validate Gas Usage in Loops (S10.1.A1)

**Vulnerable:**
```solidity
// VULNERABLE — array length re-read every iteration (SLOAD per iteration)
contract GasInefficient {
    uint256[] public data;

    function addData(uint256[] memory newData) public {
        for (uint i = 0; i < newData.length; i++) {
            data.push(newData[i]);  // ← inefficient: push is expensive
        }
    }
}
```

**Fixed:**
```solidity
// FIXED — cache array length outside loop
contract OptimizedGas {
    uint256[] public data;

    function addData(uint256[] memory newData) public {
        uint256 length = newData.length;  // cache in stack variable (MLOAD vs SLOAD)
        for (uint i = 0; i < length; i++) {
            data.push(newData[i]);
        }
    }
}
```

**How to Check:**
- Code Review: Ensure that loops and functions which deal with dynamic data structures are optimized for gas usage. Look for unnecessary state changes or excessive iterations within a single transaction.
- Gas Estimation: Use `eth-gas-reporter` or Remix IDE to estimate gas usage before and after optimizations.
- Dynamic Testing: Test the contract with various input sizes and check that it performs within reasonable gas limits.

---

## Gas Optimization Patterns

### Storage Optimization

```solidity
// EXPENSIVE — separate storage slots for each variable
uint256 public a;    // slot 0 (32 bytes)
uint256 public b;    // slot 1 (32 bytes)
uint8 public c;      // slot 2 (32 bytes wasted)
uint8 public d;      // slot 3 (32 bytes wasted)

// OPTIMIZED — pack small types into single slot
uint128 public a;    // slot 0: bytes 0-15
uint128 public b;    // slot 0: bytes 16-31
uint8 public c;      // slot 1: byte 0
uint8 public d;      // slot 1: byte 1
```

### Calldata vs Memory

```solidity
// EXPENSIVE — copies calldata to memory
function process(uint256[] memory data) external { ... }

// CHEAPER — reads directly from calldata (no copy)
function process(uint256[] calldata data) external { ... }
```

### Immutable and Constant

```solidity
// EXPENSIVE — reads from storage every time
address public owner;  // SLOAD: 2100 gas cold, 100 gas warm

// CHEAP — embedded in bytecode (no storage read)
address public immutable owner;   // reads from bytecode: ~3 gas
uint256 public constant FEE = 30; // compile-time constant: 0 gas
```

### Custom Errors (Solidity ≥0.8.4)

```solidity
// EXPENSIVE — string reverts cost gas
require(condition, "This is a long error message");

// CHEAP — custom errors are ABI-encoded (4 bytes selector)
error InsufficientBalance(address user, uint256 required, uint256 available);
if (!condition) revert InsufficientBalance(msg.sender, required, available);
```

### Events vs Storage for History

```solidity
// EXPENSIVE — storing history on-chain
struct Trade {
    address buyer;
    uint256 amount;
    uint256 timestamp;
}
Trade[] public tradeHistory;  // grows forever → expensive

// CHEAP — emit event (stored in logs, not state)
event TradeExecuted(address indexed buyer, uint256 amount, uint256 timestamp);
emit TradeExecuted(msg.sender, amount, block.timestamp);
// Query off-chain via event logs
```

---

## Chain Re-Org Risk (S10.1.B1, S7.2.B2)

Confirmation numbers determine when a transaction is considered final:

| Chain | Safe Confirmations | Notes |
|-------|---------------------|-------|
| Ethereum Mainnet | 12–32 blocks | ~2.4–6.4 min |
| Polygon PoS | 128+ blocks | ~4.3 min |
| BSC | 15–20 blocks | ~45–60 sec |
| Arbitrum | 1 (L2) + Ethereum finality (L1) | L1 finality for withdrawals |
| Optimism | 1 (L2) + 7-day challenge period (L1) | |

**Implementation:**
```solidity
// For contracts involving VRF or cross-chain operations,
// require sufficient block confirmations before using data
uint256 public constant REQUIRED_CONFIRMATIONS = 12;

function useData(bytes32 requestId) external {
    RequestData storage req = requests[requestId];
    require(block.number >= req.requestedAt + REQUIRED_CONFIRMATIONS, "Too early");
    // use data
}
```

---

## Gas Estimation Tools

```bash
# Foundry gas report
forge test --gas-report

# Gas snapshot (detect regressions)
forge snapshot
forge snapshot --check  # fails if gas increased

# eth-gas-reporter (Hardhat)
REPORT_GAS=true npx hardhat test

# Remix IDE: built-in gas estimation in debug tab
```

## L2 Integration Security (S10.2.A2)

When integrating L2 solutions:
1. Verify bridge contract security before using (check audit reports)
2. Understand sequencer centralization risks (Optimism, Arbitrum have single sequencer)
3. For state channels: verify dispute resolution mechanism
4. For rollups: verify proof system (optimistic = 7-day window, ZK = immediate finality)
