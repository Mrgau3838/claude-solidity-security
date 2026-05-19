# S8: Denial of Service (DoS)

**Control Objective:** Establish practices and mechanisms to prevent DoS attacks that can disrupt contract functionality and availability through gas exhaustion, blocking patterns, or resource abuse.

---

## S8.1 Gas Limits

### S8.1.A Efficient Loop and Function Design

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S8.1.A1 | Ensure that contracts are protected against insufficient gas griefing attacks by carefully managing gas consumption in critical functions. | | ✓ | ✓ |
| S8.1.A2 | Ensure that systems like the RocketDepositPool contract handle failures in functions like `burn()` gracefully. | | ✓ | ✓ |
| S8.1.A3 | Verify that gas usage in functions and loops is efficient to avoid out-of-gas errors. | | ✓ | ✓ |
| S8.1.A4 | Implement mechanisms to prevent denial of service attacks due to block gas limits, ensuring that transactions or operations do not exceed the gas limit constraints. | | ✓ | ✓ |

### S8.1.B Fallback Mechanisms

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S8.1.B1 | Ensure that `try/catch` blocks are provided with adequate gas to avoid failures and unexpected behavior in case of errors. | | ✓ | ✓ |

---

## S8.2 Resilience Against Resource Exhaustion

### S8.2.A Rate Limiting

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S8.2.A1 | Avoid using blocking mechanisms that could lead to a Denial-of-Service (DoS) attack. | | ✓ | ✓ |
| S8.2.A2 | Protect against potential DoS in functions like `supportsERC165InterfaceUnchecked()` by handling excessive data queries efficiently. | | ✓ | ✓ |
| S8.2.A3 | Ensure that assertions do not lead to denial of service or unexpected contract reverts, especially in scenarios where conditions are not met. | | ✓ | ✓ |
| S8.2.A4 | Verify that return values from external function calls are checked to prevent issues related to unchecked return values, which could lead to unexpected behavior. | | ✓ | ✓ |
| S8.2.A5 | Ensure that contract functions are protected against denial of service due to unexpected reverts by handling all possible error conditions appropriately. | | ✓ | ✓ |
| S8.2.A6 | Ensure that functions such as `supportsERC165InterfaceUnchecked()` in ERC165Checker.sol handle large data queries efficiently to avoid excessive resource consumption. | | ✓ | ✓ |

---

## Testing for DoS — Patterns and Fixes

### Unbounded Loop (S8.1.A3, S8.1.A4)

**Vulnerable:**
```solidity
// VULNERABLE — loop iterates over user-controlled array
contract GasDoSVulnerable {
    mapping(address => uint256) public balances;

    // Allows a user to send tokens to many recipients in one transaction
    function bulkTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Invalid input");

        for (uint256 i = 0; i < recipients.length; i++) {  // ← unbounded
            require(amounts[i] > 0, "Amount must be greater than zero");
            balances[recipients[i]] += amounts[i];
        }
    }
}
```

**Why It's Vulnerable:**
- Loop over dynamic user-supplied array with no size limit
- Attacker passes a large array → out-of-gas → transaction fails
- Legitimate users also affected (griefing)

**Fixed:**
```solidity
// FIXED — batch processing with bounded size
contract BoundedTransfer {
    uint256 public constant MAX_BATCH = 100;

    function bulkTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Invalid input");
        require(recipients.length <= MAX_BATCH, "Batch too large");

        uint256 length = recipients.length;  // cache length outside loop
        for (uint256 i = 0; i < length; i++) {
            require(amounts[i] > 0, "Amount must be greater than zero");
            balances[recipients[i]] += amounts[i];
        }
    }
}
```

**How to Check:**
- Code Review: Look for `for` or `while` loops operating on dynamic arrays or mappings without size constraints.
- Dynamic Input Testing: Test the function with a large dataset to simulate behavior near the gas limit.
- Review Documentation: Ensure the contract specifies constraints on data growth and function usage.

---

### Inefficient Nested Loops (S8.1.A3)

**Vulnerable:**
```solidity
contract NestedLoopExample {
    uint[][] public matrix;

    function processMatrix() public {
        for (uint i = 0; i < matrix.length; i++) {
            for (uint j = 0; j < matrix[i].length; j++) {
                matrix[i][j] = matrix[i][j] * 2;  // O(n²) gas cost
            }
        }
    }
}
```

**Fixed:**
```solidity
// Process in bounded batches
function processMatrixBatch(uint startRow, uint endRow) public {
    require(endRow <= matrix.length, "End row exceeds matrix size");
    for (uint i = startRow; i < endRow; i++) {
        for (uint j = 0; j < matrix[i].length; j++) {
            matrix[i][j] = matrix[i][j] * 2;
        }
    }
}
```

**How to Check:**
- Code Review: Examine nested loops and assess gas consumption relative to input size.
- Gas Profiling: Use `eth-gas-reporter` to analyze gas usage during testing.
- Dynamic Testing: Simulate scenarios with large matrix sizes.

---

### Assertion-Based DoS (S8.2.A3)

```solidity
// VULNERABLE — assert() uses all remaining gas on failure (pre-0.8.0)
// In >=0.8.0, assert() uses a Panic error but still consumes gas
assert(condition);  // Never use assert() for user-visible conditions

// FIXED — use require() with error message for user-facing conditions
require(condition, "Condition not met");

// assert() is ONLY for internal invariants that should NEVER fail:
assert(totalSupply == sumOfBalances);  // invariant check at end of critical function
```

---

### Gas Griefing in try/catch (S8.1.B1)

```solidity
// VULNERABLE — try/catch may fail if called contract uses more gas than forwarded
try externalContract.expensiveOperation{gas: 50000}() {
    // success
} catch {
    // The catch may also fail if not enough gas was forwarded for the revert reason
}

// FIXED — forward sufficient gas, account for catch overhead
uint256 gasToForward = gasleft() * 63 / 64;  // Leave 1/64 for caller overhead
try externalContract.expensiveOperation{gas: gasToForward}() {
    // success
} catch Error(string memory reason) {
    // handled
} catch (bytes memory) {
    // low-level revert
}
```

**How to Check:**
- Code Review: Search for `transfer()` (2300 gas limit — may not be enough for complex fallback functions) vs `call{value: ...}("")`.
- Verify `try/catch` blocks have adequate gas forwarding.
- Check for blocking patterns: any function that can be frozen by an attacker (e.g., transfers to contracts with reverting receive()).
- Static Analysis: Slither detectors `calls-loop`, `msg-value-loop`.
