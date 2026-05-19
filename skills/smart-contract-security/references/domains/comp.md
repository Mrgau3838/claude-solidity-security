# S11: Component-Specific Security

**Control Objective:** Establish security practices and standards for various blockchain components — tokens, NFTs, vaults, liquid staking, liquidity pools, and Uniswap V4 hooks — to mitigate component-specific vulnerabilities.

---

## S11.1 Tokens (ERC20, ERC721, ERC1155)

### S11.1.A Secure Implementation and Management

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S11.1.A1 | Verify that the `totalSupply` value is consistent during token minting operations, ensuring that callbacks do not result in incorrect values. | | ✓ | ✓ |
| S11.1.A2 | Some tokens have multiple addresses associated with them, which can introduce vulnerabilities. Ensure all token addresses are managed and verified securely to avoid related risks. | | ✓ | ✓ |
| S11.1.A3 | Verify that tokens handle zero amount transfers properly to prevent issues in integrations and operations. | | ✓ | ✓ |
| S11.1.A4 | Verify that tokens handle zero amount transfers properly to prevent issues in integrations and operations. | | ✓ | ✓ |
| S11.1.A5 | Some tokens revert on the transfer of a zero amount, which can cause issues in certain integrations and operations. Ensure compatibility with such tokens to avoid integration problems. | | ✓ | ✓ |
| S11.1.A6 | Not all ERC20 tokens comply with the EIP20 standard; some may not return a boolean flag or revert on failure. Verify compliance with the ERC20 standard to avoid compatibility issues. | | ✓ | ✓ |

**ERC20 Approval Race Condition:**
```solidity
pragma solidity ^0.5.0;

// VULNERABLE — does not check current allowance before overwriting
contract SimpleERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Approval race condition vulnerability:
    // 1. Alice approves Bob for 100
    // 2. Alice changes to approve Bob for 50
    // 3. Bob sees pending tx → spends original 100 before new tx
    // 4. Bob also spends new 50 → total 150 spent when Alice intended 50
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;  // ← VULNERABLE
        return true;
    }
}
```

**Fixed:**
```solidity
pragma solidity ^0.8.0;

contract SafeERC20 {
    mapping(address => mapping(address => uint256)) public allowance;

    // Require zero-first pattern to prevent race condition
    function approve(address spender, uint256 amount) public returns (bool) {
        require(
            amount == 0 || allowance[msg.sender][spender] == 0,
            "Approve: non-zero allowance"
        );
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // Alternative: use increaseAllowance / decreaseAllowance
}
```

**How to Check:**
- Code Review: Look for the `approve` function in token contracts — verify it includes a check for current allowance or uses the zero-first pattern.
- Static Analysis: Use SolidityScan, MythX, or Slither to check for the "approval race condition."
- Dynamic Testing: Test token transfer functionality with edge cases where allowance is set to non-zero values before calling approve.

**Non-Standard ERC20 Compatibility (S11.1.A6):**
```solidity
// VULNERABLE — assumes ERC20 returns bool
bool success = token.transfer(recipient, amount);
require(success, "Transfer failed");
// Some tokens (e.g., USDT) don't return bool → reverts unexpectedly

// FIXED — use SafeERC20 for all token interactions
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

IERC20(token).safeTransfer(recipient, amount);  // handles non-standard tokens
```

**Zero-Amount Transfer Reverting Tokens (S11.1.A5):**
```solidity
// Some tokens revert on zero-amount transfer — guard against this
function safeTransferIfNonZero(IERC20 token, address to, uint256 amount) internal {
    if (amount > 0) {
        SafeERC20.safeTransfer(token, to, amount);
    }
}
```

---

## S11.2 NFT Security

### S11.2.A Best Practices for Non-Fungible Tokens

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S11.2.A1 | Implement standards and best practices for NFT creation, management, and transfer to prevent common vulnerabilities. | | ✓ | ✓ |
| S11.2.A2 | Ensure proper metadata integrity and prevent unauthorized minting or transfers. | | ✓ | ✓ |
| S11.2.A3 | Safeguard against potential exploits related to royalty payments or token burns. | | ✓ | ✓ |

**NFT Security Checklist:**
- `safeMint()` vs `mint()` — `safeMint` calls `onERC721Received` on contract recipients (reentrancy risk if not guarded)
- Verify `_baseURI()` returns immutable IPFS CID, not a mutable HTTP URL
- Check that `tokenURI(tokenId)` reverts for non-existent tokens
- Verify royalty enforcement uses EIP-2981 standard
- Check for approval front-running in marketplace integrations

---

## S11.3 Vaults

### S11.3.A Secure Asset Storage and Management

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S11.3.A1 | Address potential overhead issues associated with withdrawing stETH or wstETH, including queue times and withdrawal limits, to ensure smooth operations. | | ✓ | ✓ |
| S11.3.A2 | Handle conversions between stETH and wstETH carefully to avoid potential issues due to the rebasing nature of stETH. | | ✓ | ✓ |

**stETH/wstETH Rebasing:**
```solidity
// DANGEROUS — stETH rebases daily (balance changes without transfer)
// If vault stores stETH amounts as fixed values, accounting breaks after rebase

// WRONG — stores stETH amount, but balance changes on rebase
uint256 public stakedAmount;  // stored at deposit time, stale after rebase

// CORRECT — use wstETH (wrapped, non-rebasing) inside vaults
// Or use shares-based accounting:
uint256 public totalShares;
mapping(address => uint256) public userShares;

function deposit(uint256 stethAmount) external {
    uint256 shares = (totalShares == 0)
        ? stethAmount
        : stethAmount * totalShares / stETH.balanceOf(address(this));
    userShares[msg.sender] += shares;
    totalShares += shares;
    stETH.transferFrom(msg.sender, address(this), stethAmount);
}
```

**ERC-4626 Vault Security (best practice):**
```solidity
// Use OpenZeppelin ERC-4626 for standardized vault accounting
// Key: convertToShares() and convertToAssets() must be consistent
// Round shares DOWN when depositing (protocol protection)
// Round assets DOWN when withdrawing (protocol protection)
```

---

## S11.4 Liquid Staking

### S11.4.A Secure Staking Mechanisms

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S11.4.A1 | Verify that mechanisms for detaching sfrxETH from frxETH are robust to prevent discrepancies and ensure accurate reward transfers, particularly when controlled by centralized entities. | | ✓ | ✓ |
| S11.4.A2 | Monitor potential future changes in the sfrxETH/ETH rate and ensure users are adequately forewarned to mitigate risks associated with rate fluctuations. | | ✓ | ✓ |

**Liquid Staking Integration Checklist:**
- Verify exchange rate is fetched from the actual staking contract, not hardcoded
- Check that rate changes are handled gracefully in dependent calculations
- Verify withdrawal queue mechanics are understood (may have delays)
- For frxETH/sfrxETH: check that reward distribution is correctly accounted

---

## S11.5 Liquidity Pools (AMMs)

### S11.5.A Security in Automated Market Makers

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S11.5.A1 | [WIP — placeholder, no active requirement] | | | |

**AMM Security Checklist (based on SCSTG guidance):**
- Flash loan protection on price-sensitive operations
- Slippage tolerance parameters (user-specified minimum output)
- Sandwich attack mitigation via minimum amount out checks
- Reentrancy guards on all swap/liquidity functions
- Fee calculation rounding in protocol's favor
- Impermanent loss understanding in documentation

---

## S11.6 Uniswap V4 Hook

### S11.6.A Secure Integration and Customization

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S11.6.A1 | Verify the correct usage of Uniswap's TickMath and FullMath libraries to ensure proper handling of unchecked arithmetic operations, adhering to version-specific Solidity considerations. | | ✓ | ✓ |

**Uniswap V4 Hook Security:**
```solidity
// TickMath and FullMath use unchecked{} for performance
// In Solidity >=0.8.0, these libraries were updated but edge cases exist

// RISKY — incorrect range for sqrtPriceX96
// TickMath.getSqrtRatioAtTick() only valid for tick in [-887272, 887272]
int24 invalidTick = 900000;  // out of range → undefined behavior
uint160 price = TickMath.getSqrtRatioAtTick(invalidTick);  // may overflow

// SAFE — validate tick bounds before use
require(tick >= TickMath.MIN_TICK && tick <= TickMath.MAX_TICK, "Invalid tick");

// FullMath.mulDiv — safe overflow-resistant multiplication
// Handles intermediate values > uint256.max using 512-bit intermediates
// SAFE to use but verify Solidity version matches library expectations
```

**V4 Hook Checklist:**
- Verify tick range validation before `TickMath` calls
- Check `FullMath.mulDiv` usage matches the Solidity version it was compiled with
- Audit unchecked arithmetic blocks in both TickMath and FullMath for the specific version
- Test with boundary values (MIN_TICK, MAX_TICK, MAX_UINT160)
- Verify hook permissions are minimal (only flags that the hook actually uses)

---

## Component-Specific Vulnerability Summary

| Component | Top Vulnerability | SCSVS Ref |
|-----------|-------------------|-----------|
| ERC20 | Approval race condition | S11.1.A3 |
| ERC20 | Non-standard return values (USDT) | S11.1.A6 |
| ERC20 | Zero-amount transfer revert | S11.1.A5 |
| ERC721 | Unauthorized minting | S11.2.A2 |
| ERC721 | Reentrancy in safeMint callbacks | S3.3.A4 |
| Vault | stETH rebasing accounting | S11.3.A2 |
| Vault | ERC-4626 rounding direction | S7.2.A6 |
| Liquid Staking | sfrxETH/frxETH detach | S11.4.A1 |
| AMM | Flash loan price manipulation | S7.2.A1 |
| Uniswap V4 | TickMath overflow | S11.6.A1 |
