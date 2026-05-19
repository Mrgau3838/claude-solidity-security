# S7: Arithmetic and Logic Security

**Control Objective:** Establish secure arithmetic practices to prevent overflow/underflow, precision loss, and logic manipulation in smart contract calculations.

---

## S7.1 Preventing Overflow/Underflow

### S7.1.A Use of Safe Math Libraries

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S7.1.A1 | Verify that explicit type casting does not lead to overflow or underflow issues. | | ✓ | ✓ |
| S7.1.A2 | Verify that integer arithmetic operations do not exceed their bounds to prevent integer overflow or underflow vulnerabilities. | | ✓ | ✓ |
| S7.1.A3 | Ensure that operations involving time units and other expressions handle potential overflows correctly. | | ✓ | ✓ |
| S7.1.A4 | Verify that division by zero is correctly handled and causes a transaction revert to prevent unexpected behavior. | | ✓ | ✓ |
| S7.1.A5 | Ensure that variables are managed within their bounds to prevent reverts due to exceeding limits. | | ✓ | ✓ |
| S7.1.A6 | Ensure that arithmetic operations within the `unchecked{}` block are carefully managed to prevent unintentional overflow or underflow. | | ✓ | ✓ |
| S7.1.A7 | Confirm that inline assembly operations handle division by zero and overflow/underflow according to desired behavior and revert appropriately. | | ✓ | ✓ |
| S7.1.A8 | Implement checks to handle cases where operations might introduce unintended precision issues or rounding errors. | | ✓ | ✓ |

### S7.1.B Fixed-Point Arithmetic

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S7.1.B1 | Verify that fixed-point arithmetic operations are performed safely to prevent overflow, underflow, and precision loss. | | ✓ | ✓ |

**Overflow in Solidity ≥0.8.0:**
```solidity
// Solidity >=0.8.0: arithmetic reverts on overflow by default
uint256 a = type(uint256).max;
uint256 b = a + 1;  // ← reverts automatically

// BUT: unchecked{} bypasses this protection
unchecked {
    uint256 result = a + 1;  // wraps to 0 silently — RISKY
}

// SAFE: validate before unchecked arithmetic (used for gas optimization)
require(b <= type(uint256).max - a, "Overflow");
unchecked { uint256 result = a + b; }
```

**Type Casting Overflow:**
```solidity
// VULNERABLE — data loss on downcast
uint256 large = 300;
uint8 small = uint8(large);  // truncates to 44 (300 % 256) — silent data loss

// FIXED — validate range before cast
require(large <= type(uint8).max, "Value too large");
uint8 small = uint8(large);
// Or use OpenZeppelin SafeCast
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
uint8 small = SafeCast.toUint8(large);  // reverts on overflow
```

**Fixed-Point Precision:**
```solidity
// VULNERABLE — integer division loses precision
function calculateReward(uint256 totalSupply, uint256 percentage) public view returns (uint256) {
    return totalSupply * percentage / 100;  // truncation for small percentages
}

// FIXED — multiply before divide, use scaling factor
uint256 constant PRECISION = 1e18;  // 18 decimal precision

function calculateReward(uint256 totalSupply, uint256 percentage) public view returns (uint256) {
    return (totalSupply * percentage * PRECISION) / 100 / PRECISION;
    // Or use WAD math: return totalSupply * percentage / 100;  (when amounts are already 1e18-scaled)
}
```

**How to Check:**
- Code Review: Audit every `unchecked{}` block — verify the developer has proven no overflow is possible.
- Search for downcasts: `uint8(x)`, `uint16(x)`, `uint32(x)` — verify range validation.
- Check division operations for potential divide-by-zero (no protection needed for Solidity >=0.8.0 on `a/b` but inline assembly bypasses this).
- Static Analysis: Slither detectors `tautology`, `incorrect-equality`, `divide-before-multiply`.

---

## S7.2 Arithmetic Integrity

### S7.2.A Secure Calculations and Logic

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S7.2.A1 | Ensure that price or rate calculations derived from asset balances are protected from manipulation, considering attack vectors like flash loans and donations. | | ✓ | ✓ |
| S7.2.A2 | Ensure that the use of structs and arrays does not lead to data corruption or incorrect values due to storage encoding issues. | | ✓ | ✓ |
| S7.2.A3 | Avoid operations that could lead to unintended data type conversions or precision loss by ensuring arithmetic operations are performed correctly. | | ✓ | ✓ |
| S7.2.A4 | Enforce a minimum transaction amount to prevent attackers from clogging the network with zero amount or dust transactions. | | ✓ | ✓ |
| S7.2.A5 | Validate that financial operations respect associative properties, ensuring consistent outcomes whether operations are performed in aggregate or iteratively. | | ✓ | ✓ |
| S7.2.A6 | Implement proper rounding direction for calculations where accounting relies on user shares to avoid inaccuracies. | | ✓ | ✓ |
| S7.2.A7 | Validate that inequalities and comparisons are correctly implemented to handle edge values appropriately. | | ✓ | ✓ |
| S7.2.A8 | Ensure that `abi.decode` adheres to the type limits to avoid reverts due to overflow of target types. | | ✓ | ✓ |
| S7.2.A9 | Ensure that logical operators such as `==`, `!=`, `&&`, `||`, and `!` are used correctly, especially when test coverage may be limited. | | ✓ | ✓ |

### S7.2.B Precondition and Postcondition Checks

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S7.2.B1 | Ensure that multiplication is performed before division to maintain precision in calculations. | | ✓ | ✓ |
| S7.2.B2 | Ensure that the request confirmation number is high enough to mitigate risks associated with chain re-orgs. | | ✓ | ✓ |
| S7.2.B3 | Verify that off-by-one errors are avoided in loops and iterations, ensuring correct handling of list lengths and indexing. | | ✓ | ✓ |
| S7.2.B4 | Verify that unsigned integers are not used to represent negative values, as this can lead to erroneous behavior. | | ✓ | ✓ |
| S7.2.B5 | Verify that calculations with multiple terms handle all possible edge cases for min/max values to avoid errors. | | ✓ | ✓ |

**Flash Loan Price Manipulation (S7.2.A1):**
```solidity
// VULNERABLE — spot price from current balance (manipulable via flash loan)
function getPrice() public view returns (uint256) {
    return tokenBalance / ethBalance;  // TWAP-free spot price
}

// ATTACKED:
// 1. Flash loan large ETH
// 2. Dump into pool → price drops
// 3. Exploit low price (e.g., borrow more than collateral)
// 4. Repay flash loan

// FIXED — use TWAP (Time-Weighted Average Price) from Uniswap V3
// or use Chainlink price feed with freshness checks
```

**Rounding Direction (S7.2.A6):**
```solidity
// In lending protocols: round in favor of protocol, not user
// When calculating debt: round UP (user owes more, not less)
// When calculating collateral: round DOWN (user gets less, not more)

// RISKY — standard division rounds down for both
uint256 debt = (principal * interestRate) / PRECISION;  // rounds down = user benefits

// FIXED — use ceiling division for debt calculations
uint256 debt = (principal * interestRate + PRECISION - 1) / PRECISION;  // rounds up
```

**Multiply Before Divide (S7.2.B1):**
```solidity
// WRONG — divide first, then multiply (loses precision)
uint256 result = (a / b) * c;

// CORRECT — multiply first, then divide
uint256 result = (a * c) / b;
```

**Off-by-One in Loops (S7.2.B3):**
```solidity
// VULNERABLE — off-by-one error skips last element or reads out of bounds
for (uint i = 0; i <= array.length; i++) {  // ← should be < not <=
    process(array[i]);  // array[array.length] is out of bounds
}

// FIXED
for (uint i = 0; i < array.length; i++) {
    process(array[i]);
}
```

**How to Check:**
- Code Review: Every price calculation — is it TWAP-based or spot? Spot prices are manipulable.
- Check all division operations: multiplication should come first.
- Audit rounding direction in lending/staking math — debt rounds up, collateral rounds down.
- Dynamic Testing: Test with extreme values (0, 1, `type(uint256).max`) to find edge cases.
- Static Analysis: Slither detector `divide-before-multiply`.
