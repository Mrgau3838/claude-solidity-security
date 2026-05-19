# Developer Quick-Check Workflow

Fast inline security review for developers. Triage findings and provide actionable fixes.

---

## Step 1 — Triage the Request

Identify what the developer is asking:

| Request type | Action |
|-------------|--------|
| "Is this safe?" / paste of code | Run quick scan → identify top risks |
| Specific vulnerability question | Jump to relevant domain file |
| "Fix this bug" / specific issue | Provide fix + SCSVS reference |
| "Why is my transfer failing?" | Diagnose + security check |

---

## Step 2 — Quick Scan (30 seconds)

When given Solidity code, immediately check these high-frequency issues:

### Top-10 Instant Checks

```
[ ] 1. tx.origin used for auth? → S4.2.A1 — replace with msg.sender
[ ] 2. External call before state update? → S3.3.A4 — CEI pattern
[ ] 3. Missing nonReentrant? → S3.3.A3 — add on fund-touching functions
[ ] 4. Unchecked return value on .call()? → S5.1.A1
[ ] 5. delegatecall to user-controlled address? → S5.1.A3
[ ] 6. block.timestamp for randomness? → S6.3.A1 — use Chainlink VRF
[ ] 7. Unbounded loop over user-controlled array? → S8.1.A3
[ ] 8. approve() without zero-first pattern? → S11.1.A3
[ ] 9. ecrecover() result not checked for zero? → S6.1.A1
[ ] 10. Hardcoded admin address? → S4.1.A1
```

---

## Step 3 — Inline Feedback Format

For each issue found, respond with:

```
⚠️ [SEVERITY] <Issue Title>
SCSVS: <ID>
Line: <line number if available>
Problem: <one sentence>
Fix:
  <corrected code snippet>
```

Severity icons: 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ℹ️ Info

---

## Step 4 — Common Patterns & Fixes

### Reentrancy (S3.3)
```solidity
// VULNERABLE — state updated after external call
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");  // external call first
    balances[msg.sender] -= amount;                   // state after ← BAD
}

// FIXED — Check-Effects-Interactions
function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;                   // state first
    (bool ok,) = msg.sender.call{value: amount}("");  // call last
    require(ok, "Transfer failed");
}
```

### tx.origin Authorization (S4.2.A1, S4.1.C1)
```solidity
// VULNERABLE
modifier onlyOwner() {
    require(tx.origin == owner);  // ← phishing attack vector
    _;
}

// FIXED
modifier onlyOwner() {
    require(msg.sender == owner);
    _;
}
```

### Unchecked External Call (S5.1.A1)
```solidity
// VULNERABLE
token.transfer(recipient, amount);  // ERC20 transfer — may return false

// FIXED — use SafeERC20 or check return value
require(token.transfer(recipient, amount), "Transfer failed");
// or: SafeERC20.safeTransfer(token, recipient, amount);
```

### Integer Overflow/Underflow (S7.1.A2)
```solidity
// Solidity >=0.8.0: overflow reverts automatically (unless unchecked{})
// In unchecked{} blocks, you must validate manually:
unchecked {
    // RISKY if a + b > type(uint256).max
    uint256 result = a + b;
}

// SAFE — validate before unchecked
require(a <= type(uint256).max - b, "Overflow");
unchecked { uint256 result = a + b; }
```

### ERC20 Approval Race Condition (S11.1.A3)
```solidity
// VULNERABLE — does not check current allowance
function approve(address spender, uint256 amount) public returns (bool) {
    allowance[msg.sender][spender] = amount;
    return true;
}

// FIXED — require zero-first or use increaseAllowance
function approve(address spender, uint256 amount) public returns (bool) {
    require(amount == 0 || allowance[msg.sender][spender] == 0,
            "Approve: non-zero allowance");
    allowance[msg.sender][spender] = amount;
    return true;
}
```

### Weak Randomness (S6.3.A1)
```solidity
// VULNERABLE — miner-manipulable
uint random = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));

// FIXED — Chainlink VRF
// See: https://docs.chain.link/vrf/v2/introduction
// requestRandomWords() + fulfillRandomWords() pattern
```

### Pull vs Push Withdrawal (S3.1.A1)
```solidity
// VULNERABLE — push can fail/block if recipient is a contract
function distributeRewards() external {
    for (uint i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(rewards[i]);  // DoS vector
    }
}

// FIXED — pull pattern
mapping(address => uint) public pendingRewards;

function claimReward() external nonReentrant {
    uint amount = pendingRewards[msg.sender];
    require(amount > 0, "No reward");
    pendingRewards[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}
```

### delegatecall Return Value (S5.1.A5)
```solidity
// VULNERABLE — returns success/failure of the call, NOT the inner execution
(bool success, ) = target.delegatecall(data);
// success = true even if the delegated function reverted

// FIXED — decode return data or use assembly to propagate revert
(bool success, bytes memory returnData) = target.delegatecall(data);
if (!success) {
    assembly { revert(add(returnData, 32), mload(returnData)) }
}
```

---

## Step 5 — When to Escalate to Full Audit

Recommend a full audit if:
- Contract holds or manages user funds
- Contract uses proxy/upgradeable patterns
- Contract integrates with external protocols (DeFi, oracles, bridges)
- Contract has complex tokenomics or governance mechanisms
- TVL > $100K or significant number of users expected

---

## Quick Reference: Slither One-Liner

```bash
# Install: pip install slither-analyzer
slither contracts/MyContract.sol --print human-summary 2>/dev/null
slither contracts/MyContract.sol --detect reentrancy-eth,arbitrary-send-eth,controlled-delegatecall
```
