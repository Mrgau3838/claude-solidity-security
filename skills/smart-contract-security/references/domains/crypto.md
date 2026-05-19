# S6: Cryptographic Practices

**Control Objective:** Establish secure cryptographic practices for key management, signature verification, and random number generation.

---

## S6.1 Key Management

### S6.1.A Secure Handling and Storage of Private Keys

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S6.1.A1 | Verify that the `ecrecover()` function handles malformed inputs correctly and does not return invalid data. | | ✓ | ✓ |
| S6.1.A2 | Ensure that signature verification mechanisms are robust against signature malleability and replay attacks, particularly by using nonces or hashed messages rather than relying solely on the signature itself. | | ✓ | ✓ |
| S6.1.A3 | Verify that `SignatureChecker.isValidSignatureNow` handles edge cases properly and does not revert unexpectedly, considering the ABI decoding issues introduced in Solidity 0.8. | | ✓ | ✓ |
| S6.1.A4 | Ensure that all signatures are checked thoroughly to prevent unauthorized transactions or actions due to weak or improperly managed signature validation. | | ✓ | ✓ |
| S6.1.A5 | Validate that signature protection mechanisms are up-to-date and resistant to signature malleability attacks by avoiding outdated libraries and practices. | | ✓ | ✓ |

### S6.1.B Multi-Signature Wallets

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S6.1.B1 | Verify that multi-signature wallets require a predefined number of signatures before executing any transaction. | | ✓ | ✓ |
| S6.1.B2 | Ensure that the multi-signature wallet logic is resistant to replay attacks. | | ✓ | ✓ |
| S6.1.B3 | Verify that the process of adding or removing signatories from the multi-signature wallet is secure and controlled. | | ✓ | ✓ |

**ecrecover() Zero-Address Check (S6.1.A1):**
```solidity
// VULNERABLE — ecrecover returns address(0) for invalid/malformed signatures
address signer = ecrecover(hash, v, r, s);
// No check: if malformed input, signer == address(0)
// If owner is stored as address(0) anywhere, this becomes auth bypass

// FIXED — always validate result
address signer = ecrecover(hash, v, r, s);
require(signer != address(0), "Invalid signature");
require(signer == expectedSigner, "Unauthorized");
```

**Signature Malleability (S6.1.A2):**
```solidity
// VULNERABLE — raw ecrecover is malleable
// ECDSA signatures have two valid (r,s) pairs for the same message
// An attacker can flip s to s = secp256k1.n - s to create a valid variant
// This allows using the same signature twice if only the raw sig is tracked

// FIXED — use OpenZeppelin ECDSA library
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function verify(bytes32 messageHash, bytes calldata sig) public {
    address signer = ECDSA.recover(messageHash, sig);
    // OZ ECDSA.recover enforces s <= secp256k1.n/2 to prevent malleability
    require(signer == authorizedSigner, "Invalid signature");
}
```

**Replay Protection with Nonces:**
```solidity
mapping(address => uint256) public nonces;

struct PermitData {
    address owner;
    address spender;
    uint256 value;
    uint256 nonce;
    uint256 deadline;
}

function permit(PermitData calldata data, bytes calldata sig) external {
    require(block.timestamp <= data.deadline, "Expired");
    require(data.nonce == nonces[data.owner]++, "Invalid nonce");

    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH,
        data.owner, data.spender, data.value, data.nonce, data.deadline));
    bytes32 hash = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(hash, sig);
    require(signer == data.owner, "Invalid signature");
}
```

**How to Check:**
- Code Review: Every `ecrecover()` call must check `!= address(0)`.
- Verify nonces are used in all off-chain signature schemes.
- Check OpenZeppelin ECDSA version ≥4.7.3 (fixed malleability in compact signatures).
- Static Analysis: Slither detector `arbitrary-send-eth` can catch signature bypass.

---

## S6.2 Signature Verification

### S6.2.A Cryptographic Techniques for Authentication

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S6.2.A1 | Ensure that cryptographic algorithms used for signature verification are secure and follow best practices. | | ✓ | ✓ |

### S6.2.B Standard Compliance (EIP-712)

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S6.2.B1 | Verify that ECDSA signature handling functions, such as `ECDSA.recover` and `ECDSA.tryRecover`, properly manage signature formats to prevent signature malleability, especially when handling both traditional 65-byte and EIP-2098 compact signatures. | | ✓ | ✓ |

**EIP-712 Typed Structured Data:**
```solidity
// Domain separator includes chain-specific fields
bytes32 private immutable _domainSeparator;

constructor() {
    _domainSeparator = keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("MyProtocol")),
        keccak256(bytes("1")),
        block.chainid,       // prevents cross-chain replay
        address(this)        // prevents cross-contract replay
    ));
}

function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
    return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
}
```

**How to Check:**
- Code Review: Verify domain separator includes `chainId` and `verifyingContract`.
- Check ECDSA library handles both 65-byte (`r,s,v`) and 64-byte EIP-2098 compact format.
- Verify no raw `ecrecover()` — always use OZ ECDSA wrapper.

---

## S6.3 Secure Random Number Generation

### S6.3.A Best Practices for Randomness

| Ref | Requirement | L1 | L2 | L3 |
|-----|-------------|----|----|-----|
| S6.3.A1 | Ensure that random number generation follows best practices and uses secure sources of entropy. | | ✓ | ✓ |
| S6.3.A2 | Verify that any random number generation is resistant to manipulation and prediction. | | ✓ | ✓ |

**Weak Randomness (Anti-Patterns):**
```solidity
// VULNERABLE — block variables are miner-manipulable / predictable
uint random1 = uint(keccak256(abi.encodePacked(block.timestamp)));
uint random2 = uint(keccak256(abi.encodePacked(block.difficulty)));  // deprecated post-Merge
uint random3 = uint(keccak256(abi.encodePacked(blockhash(block.number - 1))));
// All of the above: miners can manipulate, or values are predictable on-chain
```

**Chainlink VRF v2 (Correct Pattern):**
```solidity
// FIXED — Chainlink VRF for secure randomness
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract SecureLottery is VRFConsumerBaseV2 {
    VRFCoordinatorV2Interface immutable coordinator;
    uint64 subscriptionId;
    bytes32 keyHash;
    mapping(uint256 => address) requestIdToPlayer;

    function requestRandom() external returns (uint256 requestId) {
        requestId = coordinator.requestRandomWords(
            keyHash, subscriptionId, 3, 100000, 1  // confirmations, gasLimit, numWords
        );
        requestIdToPlayer[requestId] = msg.sender;
    }

    // Called by Chainlink node — validate requestId comes from coordinator
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords)
        internal override
    {
        address player = requestIdToPlayer[requestId];
        require(player != address(0), "Invalid requestId");  // S5.3.A1
        uint256 outcome = randomWords[0] % 100;
        // process outcome...
        delete requestIdToPlayer[requestId];
    }
}
```

**How to Check:**
- Code Review: Search for `block.timestamp`, `block.difficulty`, `blockhash` used as randomness — all are insecure.
- Verify Chainlink VRF `requestId` is validated in `fulfillRandomWords` (S5.3.A1).
- Check minimum confirmation count for VRF requests (prevents front-running reorg attacks).
- Dynamic Testing: Simulate miner control of block variables to demonstrate predictability.
