# Smart Contract Taxonomy

Based on OWASP SCSTG v0.0.1. Classify the contract type first — it determines which S11 subsections apply and which domains carry the highest risk.

---

## 13 Contract Types

### 1. Token Contracts
**Examples:** ERC20, ERC721 (NFT), ERC1155 (multi-token), stablecoins, wrapped assets  
**Primary SCSVS domains:** S11.1 (tokens), S11.2 (NFTs), S3.1 (economic models)  
**Key risks:**
- ERC20 approval race condition (S11.1.A3)
- totalSupply manipulation via callbacks (S11.1.A1)
- Non-standard transfer return values breaking integrations (S11.1.A6)
- Zero-amount transfer reversions (S11.1.A5)
- Unauthorized NFT minting/transfer (S11.2.A2)
- NFT royalty/burn exploits (S11.2.A3)

### 2. Crowdfunding/ICO Contracts
**Examples:** Presale, token launch, vesting  
**Primary SCSVS domains:** S3 (business logic), S4 (access control), S7 (arithmetic)  
**Key risks:**
- Integer overflow in contribution calculations (S7.1.A2)
- Reentrancy on refund functions (S3.3.A4)
- Pull vs push withdrawal pattern (S3.1.A1)
- Admin key compromise (S4.1.A1)

### 3. Governance Contracts
**Examples:** DAO governance, on-chain voting, timelock  
**Primary SCSVS domains:** S4 (access control), S3.2 (tokenomics), S6 (crypto)  
**Key risks:**
- Flash loan governance attacks (S7.2.A1)
- tx.origin authorization bypass (S4.2.A1)
- Signature replay attacks (S6.1.A2)
- EIP-712 misconfiguration (S4.3.B2)
- Insufficient confirmation numbers for chain reorgs (S7.2.B2)

### 4. DeFi Protocols
**Examples:** Lending (Aave-like), yield farming, interest rate models  
**Primary SCSVS domains:** S3, S7, S8, S11  
**Key risks:**
- Price/rate manipulation via flash loans (S7.2.A1)
- Reentrancy in liquidation callbacks (S3.3.A4)
- Rounding direction attacks (S7.2.A6)
- Minimum transaction enforcement to prevent dust attacks (S7.2.A4)

### 5. Oracle Contracts
**Examples:** Chainlink adapters, TWAP oracles, price feeds  
**Primary SCSVS domains:** S5.2 (oracle integrations), S7.2 (arithmetic integrity)  
**Key risks:**
- Single-source oracle manipulation (S5.2.B1)
- Missing fallback on oracle failure (S5.2.A3)
- Stale data acceptance (S5.2.A2)
- Chainlink VRF parameter validation (S5.3.A1)
- TWAP manipulation in low-liquidity pools (S7.2.A1)

### 6. Escrow Contracts
**Examples:** Multi-party payment release, conditional transfers  
**Primary SCSVS domains:** S3 (business logic), S4 (access control), S9.1 (state management)  
**Key risks:**
- Reentrancy on fund release (S3.3.A4)
- State corruption on dispute resolution (S9.1.A2)
- ETH locking in payable functions (S9.1.A1)

### 7. Lottery/Gaming Contracts
**Examples:** On-chain randomness, prize distribution  
**Primary SCSVS domains:** S6.3 (randomness), S3.1 (economic models)  
**Key risks:**
- Weak randomness (block.timestamp, block.difficulty) (S6.3.A1)
- Miner manipulation of outcome (S6.3.A2)
- Chainlink VRF fulfillRandomWords parameter validation (S5.3.A1)
- Pull pattern for prize claims (S3.1.A1)

### 8. Identity & Access Management (IAM) Contracts
**Examples:** Role registry, permission contract, multisig wallets  
**Primary SCSVS domains:** S4 (full), S6 (crypto)  
**Key risks:**
- Privilege escalation (S4.1.A3)
- Insecure role assignment (S4.1.A2)
- Multi-sig replay attacks (S6.1.B2)
- tx.origin phishing (S4.2.A1)

### 9. Bridge Contracts
**Examples:** Lock-and-mint bridges, atomic swap bridges, message passing  
**Primary SCSVS domains:** S5.3 (cross-chain), S5.4 (bridges), S6 (crypto)  
**Key risks:**
- Double-spending / replay attacks (S5.4.A2)
- Cross-chain message validation (S5.3.A2)
- Block reorg handling with CREATE opcode (S5.3.A3)
- Cross-chain replay attack (S5.3.A4)
- Fallback for failed cross-chain transactions (S5.4.A4)

### 10. Supply Chain / Provenance Contracts
**Examples:** Traceability, certificate registry, product authenticity  
**Primary SCSVS domains:** S4, S9 (state management)  
**Key risks:**
- Unauthorized state updates (S9.1.A)
- Event logging integrity (S9.3.A1)
- Access control on provenance writes (S4.2.A3)

### 11. Gaming / NFT Gaming Contracts
**Examples:** Play-to-earn, in-game items, character NFTs  
**Primary SCSVS domains:** S11.2 (NFTs), S6.3 (randomness), S3 (business logic)  
**Key risks:**
- Item duplication bugs (S11.2.A2)
- Predictable randomness in drop mechanics (S6.3.A1)
- Reentrancy on reward claims (S3.3.A4)
- ERC1155 callback exploitation (S11.1.A3)

### 12. Security Tool Contracts
**Examples:** Circuit breakers, pause mechanisms, multi-sig guardians  
**Primary SCSVS domains:** S4 (access control), S8 (DoS)  
**Key risks:**
- Unauthorized pause/unpause (S4.1.A1)
- DoS on pause mechanism (S8.2.A5)
- Griefing attacks (S8.1.A1)

### 13. Arbitrage / MEV Contracts
**Examples:** Flash loan arbitrage, sandwich bots, liquidation bots  
**Primary SCSVS domains:** S7 (arithmetic), S5 (interactions)  
**Key risks:**
- Flash loan manipulation of price calculations (S7.2.A1)
- Slippage exploitation in AMMs (S11.5.A1)
- Uniswap V4 TickMath/FullMath overflow (S11.6.A1)
- Front-running vulnerability in atomic operations (S5.3.B1)

---

## Domain Risk Matrix by Contract Type

| Type | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 | S11 |
|------|----|----|----|----|----|----|----|----|----|-----|-----|
| Token | M | L | M | M | L | L | M | L | M | L | **H** |
| Crowdfunding | L | L | **H** | **H** | L | L | **H** | M | L | L | M |
| Governance | M | L | M | **H** | L | **H** | M | L | L | L | M |
| DeFi | M | L | **H** | M | **H** | M | **H** | **H** | M | M | **H** |
| Oracle | L | L | L | M | **H** | M | **H** | L | L | L | L |
| Escrow | L | L | **H** | M | L | L | M | L | **H** | L | L |
| Lottery | L | L | M | L | M | **H** | L | L | L | L | L |
| IAM | M | L | L | **H** | L | **H** | L | L | L | L | L |
| Bridge | **H** | L | L | M | **H** | **H** | M | L | M | L | L |
| Supply Chain | L | M | L | **H** | L | L | L | L | **H** | L | L |
| NFT Gaming | L | L | **H** | M | L | **H** | M | L | L | L | **H** |
| Security Tools | M | L | L | **H** | L | L | L | **H** | L | L | L |
| Arbitrage/MEV | L | L | M | L | M | L | **H** | L | L | M | **H** |

**H** = High risk, **M** = Medium, **L** = Low

---

## Verification Level Selection

| Contract Type | Recommended Level |
|--------------|-------------------|
| Simple utility / helper | L1 |
| Token (small cap, non-DeFi) | L1–L2 |
| Token (DeFi-integrated, significant TVL) | L2–L3 |
| Governance | L2–L3 |
| DeFi protocol (lending/AMM) | L2–L3 |
| Bridge / cross-chain | L3 |
| Oracle infrastructure | L2–L3 |
| Mission-critical (>$10M TVL) | L3 |
