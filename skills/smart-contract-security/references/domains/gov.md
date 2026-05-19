# S3: Business Logic and Economic Security

**Control Objective:** Ensure that the contract's economic model is sound, business logic is reentrancy-safe, and tokenomics are resistant to manipulation.

---

## S3.1 Economic Models

### S3.1.A Withdrawal and Fund Management

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S3.1.A1 | Ensure that smart contracts implement pull-based withdrawal patterns over push-based fund distribution to mitigate DoS risks. | ✓ | ✓ | ✓ |
| S3.1.A2 | Verify that the tokenomics are well-documented and designed to prevent economic attacks or market manipulation. | | ✓ | ✓ |
| S3.1.A3 | Check that the contract has been tested for sufficient liquidity in scenarios that stress-test economic models. | | ✓ | ✓ |

**Pull vs Push Withdrawal:**
```solidity
// VULNERABLE — push pattern
// If recipient is a contract that reverts, all distributions fail (DoS)
function distributeDividends() external {
    for (uint i = 0; i < shareholders.length; i++) {
        payable(shareholders[i]).transfer(dividends[i]);  // ← DoS vector
    }
}

// FIXED — pull pattern
mapping(address => uint) public pendingWithdrawals;

function withdraw() external nonReentrant {
    uint amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to withdraw");
    pendingWithdrawals[msg.sender] = 0;  // state update first (CEI)
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}
```

**How to Check:**
- Code Review: Look for `transfer()` or `send()` inside loops iterating over dynamic arrays — high-risk DoS pattern.
- Verify `pendingWithdrawals` / credit-based pattern is used for distributing to multiple parties.

---

## S3.2 Tokenomics

### S3.2.A Token Security and Economic Design

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S3.2.A1 | Verify that the token distribution mechanism is transparent and prevents unfair advantages or early exploits. | | ✓ | ✓ |
| S3.2.A2 | Ensure that the token contract is resistant to market manipulation, including front-running and flash loan attacks. | | ✓ | ✓ |
| S3.2.A3 | Check that inflation and deflation mechanisms are correctly implemented and cannot be gamed. | | ✓ | ✓ |
| S3.2.A4 | Verify that the economic models of the token are sustainable and do not lead to death spiral scenarios. | | | ✓ |
| S3.2.A5 | Ensure that liquidity mechanisms are in place to maintain the token's utility and value stability. | | | ✓ |

**How to Check:**
- Code Review: Verify no uncapped minting with single-owner auth; require multi-sig for inflation events.
- Check for front-running vectors in price discovery or mint functions.
- Review for flash loan attack surfaces: does any function calculate prices using `balanceOf(address(this))`? (manipulable via flash loan donation).

---

## S3.3 Reentrancy

### S3.3.A Reentrancy Prevention

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S3.3.A1 | Verify that the smart contract uses the Check-Effects-Interactions (CEI) pattern to prevent reentrancy attacks. | | ✓ | ✓ |
| S3.3.A2 | Ensure that the contract is protected against reentrancy in batch operations and multiple-contract interactions. | | ✓ | ✓ |
| S3.3.A3 | Verify that the `nonReentrant` (or equivalent reentrancy guard) modifier is applied before any other modifiers in the function signature. | | ✓ | ✓ |
| S3.3.A4 | Check that the Check-Effects-Interactions pattern is consistently applied: state changes occur before external calls. | | ✓ | ✓ |
| S3.3.A5 | Ensure that reentrancy scenarios are tested in the test suite, including cross-function reentrancy. | | ✓ | ✓ |

**Vulnerable — Classic Reentrancy:**
```solidity
// VULNERABLE — external call before state update
mapping(address => uint) public balances;

function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    // ← attacker's fallback re-enters here, balance still non-zero
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount;  // state updated AFTER call
}
```

**Fixed — Check-Effects-Interactions:**
```solidity
// FIXED — state before external call
function withdraw(uint amount) public nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;              // effects first
    (bool ok,) = msg.sender.call{value: amount}(""); // then interaction
    require(ok, "Transfer failed");
}
```

**Modifier Ordering (S3.3.A3):**
```solidity
// WRONG — reentrancy guard applied after access check
// The access check may contain external calls that can be reentered
function sensitive() public onlyOwner nonReentrant { ... }

// CORRECT — reentrancy guard first
function sensitive() public nonReentrant onlyOwner { ... }
```

**Cross-Function Reentrancy:**
```solidity
// VULNERABLE — withdraw and transfer share state
// Attacker calls withdraw(), re-enters via transfer(), drains funds
mapping(address => uint) public balances;

function withdraw() external {
    uint bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}("");  // ← reentrancy point
    balances[msg.sender] = 0;
}

function transfer(address to, uint amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

**How to Check:**
- Code Review: For every external call (`call()`, `transfer()`, `send()`, ERC20 interactions), verify state is updated before the call.
- Static Analysis: Slither detectors `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign`, `reentrancy-events`.
- Dynamic Testing: Deploy an attacker contract whose fallback function calls back into the target. Run with Foundry fuzz tests.
