# S5: Secure Interactions (Contract-to-Contract)

**Control Objective:** Ensure that all external calls, oracle integrations, cross-chain messages, and bridge transactions are handled securely with proper validation and failure handling.

---

## S5.1 External Calls

### S5.1.A Secure External Call Handling

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.1.A1 | Ensure that the return values of low-level calls (`.call()`, `.send()`) are checked to handle failures appropriately. | | ✓ | ✓ |
| S5.1.A2 | Verify that the contract is protected against reentrancy attacks that can occur when executing callbacks from external contracts. | | ✓ | ✓ |
| S5.1.A3 | Check that the risks associated with `call()` vs `delegatecall()` are understood: `delegatecall()` executes in the context of the calling contract (storage, address), not the callee. | | ✓ | ✓ |
| S5.1.A4 | Verify that the contract checks ETH balance before and after an external call to detect unexpected changes. | | ✓ | ✓ |
| S5.1.A5 | Ensure that `delegatecall()` return values are properly verified — it returns the success/failure of the call mechanics, NOT the outcome of the delegated execution. | | ✓ | ✓ |

### S5.1.B Minimal Trusted Surface

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.1.B1 | Verify that the smart contract minimizes its trusted surface by only interacting with other contracts through well-defined and limited interfaces. | | ✓ | ✓ |
| S5.1.B2 | Ensure that the smart contract includes checks to validate the trustworthiness and authenticity of interacting parties before executing sensitive operations. | | ✓ | ✓ |
| S5.1.B3 | Check that the smart contract's interactions are designed to avoid dependencies on external data or contracts that could compromise security. | | ✓ | ✓ |
| S5.1.B4 | Verify that the contract handles failures or unexpected behaviors from external interactions gracefully to avoid cascading failures. | | ✓ | ✓ |
| S5.1.B5 | Ensure that interactions with other contracts are monitored and audited to detect and address any unusual or unauthorized activities. | | ✓ | ✓ |

**Unchecked Return Value:**
```solidity
// VULNERABLE — transfer failure silently ignored
token.transfer(recipient, amount);  // returns bool, not checked

// FIXED — use SafeERC20 or explicit check
require(token.transfer(recipient, amount), "Transfer failed");
// or: SafeERC20.safeTransfer(token, recipient, amount);
```

**delegatecall Return Value (S5.1.A5):**
```solidity
// VULNERABLE — success means the call happened, not that it succeeded
(bool success,) = target.delegatecall(data);
// success = true even if the delegated function reverted internally

// FIXED — propagate inner revert
(bool success, bytes memory returnData) = target.delegatecall(data);
if (!success) {
    assembly { revert(add(returnData, 32), mload(returnData)) }
}
```

**How to Check:**
- Code Review: Search for `.call(`, `.send(`, `.transfer(` — verify return value checked.
- Search for `delegatecall` — verify return value handling propagates inner reverts.
- Static Analysis: Slither detectors `unchecked-lowlevel`, `unchecked-send`, `controlled-delegatecall`.

---

## S5.2 Oracle Integrations

### S5.2.A Secure Data Feeds

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.2.A1 | Verify that the smart contract uses oracles that provide secure and tamper-proof data feeds, including checks for data integrity and authenticity. | | ✓ | ✓ |
| S5.2.A2 | Ensure that the smart contract validates the data received from oracles to prevent malicious or incorrect data from affecting contract operations. | | ✓ | ✓ |
| S5.2.A3 | Check that the smart contract includes fallback mechanisms in case of oracle failure or unreliable data. | | ✓ | ✓ |
| S5.2.A4 | Verify that the integration with oracles follows best practices for data security, including encryption and secure communication channels. | | ✓ | ✓ |
| S5.2.A5 | Ensure that the smart contract's oracle integration is designed to handle any potential discrepancies or conflicts in data from multiple sources. | | ✓ | ✓ |

### S5.2.B Decentralized Oracles

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.2.B1 | Verify that the smart contract uses decentralized oracles to enhance data reliability and prevent single points of failure or manipulation. | | ✓ | ✓ |
| S5.2.B2 | Ensure that the smart contract includes mechanisms to validate the consensus or majority opinion of decentralized oracles before taking actions based on their data. | | ✓ | ✓ |
| S5.2.B3 | Check that the smart contract accounts for potential latency or delays in data from decentralized oracles to maintain operational reliability. | | ✓ | ✓ |
| S5.2.B4 | Verify that the smart contract includes checks to prevent manipulation or collusion among decentralized oracles. | | ✓ | ✓ |
| S5.2.B5 | Ensure that the decentralized oracle integration adheres to standards for security and reliability in multi-oracle environments. | | ✓ | ✓ |

**Stale Price Validation (Chainlink example):**
```solidity
// VULNERABLE — no staleness check
(, int256 price,,,) = priceFeed.latestRoundData();

// FIXED — validate freshness and sanity
(uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound)
    = priceFeed.latestRoundData();
require(price > 0, "Invalid price");
require(updatedAt >= block.timestamp - MAX_STALENESS, "Stale price");
require(answeredInRound >= roundId, "Incomplete round");
```

---

## S5.3 Cross-Chain Interactions

### S5.3.A Handling External Calls Securely

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.3.A1 | Ensure that parameters for Chainlink VRF (Verifiable Random Function) are thoroughly validated to prevent the `fulfillRandomWord` function from returning incorrect values instead of reverting. | | ✓ | ✓ |
| S5.3.A2 | Implement robust security checks for cross-chain messaging to ensure correct permissions and intended functionality. | | ✓ | ✓ |
| S5.3.A3 | Verify that contracts created using the `CREATE` opcode handle block reorganizations securely to prevent unexpected eliminations. | | ✓ | ✓ |
| S5.3.A4 | Ensure robust cross-chain messaging security checks to prevent replay attacks where signatures valid on one chain might be exploited on another. | | ✓ | ✓ |

### S5.3.B Atomic Swaps

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.3.B1 | Verify that the smart contract supports atomic swaps with robust mechanisms to ensure that swaps are completed successfully or not executed at all. | | ✓ | ✓ |
| S5.3.B2 | Ensure that the smart contract includes checks to validate the atomic swap conditions and prevent partial or fraudulent swaps. | | ✓ | ✓ |
| S5.3.B3 | Check that the smart contract handles potential failures or disputes in atomic swaps securely and fairly. | | ✓ | ✓ |
| S5.3.B4 | Verify that the atomic swap functionality is tested thoroughly to cover various scenarios and edge cases. | | ✓ | ✓ |

---

## S5.4 Bridges

### S5.4.A Cross-Chain Transaction Security

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S5.4.A1 | Verify that the smart contract for cross-chain transactions includes robust mechanisms for verifying and validating transactions across different chains. | | ✓ | ✓ |
| S5.4.A2 | Ensure that the smart contract prevents double-spending and replay attacks in cross-chain transactions by implementing appropriate security checks. | | ✓ | ✓ |
| S5.4.A3 | Check that the cross-chain transaction contract handles communication and data integrity securely between different blockchain networks. | | ✓ | ✓ |
| S5.4.A4 | Verify that the smart contract includes fallback and recovery mechanisms for handling failures or inconsistencies in cross-chain transactions. | | ✓ | ✓ |

**Cross-Chain Replay Prevention:**
```solidity
// Domain separator must include chainId to prevent cross-chain replay
bytes32 public domainSeparator = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
    keccak256("Bridge"),
    block.chainid,  // ← must be chain-specific
    address(this)
));

// Message ID prevents replay within same chain
mapping(bytes32 => bool) public processedMessages;

function receiveMessage(bytes32 messageId, ...) external {
    require(!processedMessages[messageId], "Already processed");
    processedMessages[messageId] = true;
    // process message
}
```

**How to Check:**
- Code Review: For bridge contracts, verify message IDs or nonces are tracked and rejected on re-use.
- Check `chainId` is included in all signature schemes used for cross-chain authorization.
- Verify Chainlink VRF `requestId` is stored and validated in `fulfillRandomWords`.
- Static Analysis: Slither detector `msg-value-loop` for cross-chain value handling.
