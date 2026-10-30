# PrimeIdRevocationRegistry

An issuer revokes a credential by signing with its PrimeID issuer key (secp256k1, the same curve
Ethereum uses). The contract recovers the signer with `ecrecover` and records the credential as
revoked under that issuer's address. Any wallet can submit the transaction and pay the gas, but only
the issuer's key can produce a valid revocation. Only random 16-byte credential ids go on chain,
never claim values.

- The issuer signs `digest(id)`, which is the EIP-191 hash of `keccak256(registry ‖ chainid ‖ id)`.
  A signature therefore cannot be replayed on another chain or another registry.
- `isRevoked(issuerAddress, id)` is a free read. The verifier calls it with `eth_call` and fails
  closed if the call fails.
- The client side is `packages/core-crypto/registry.ts`, tested in `registry.test.ts`.

## Deploy to ZKsync Sepolia

You need a wallet funded with Sepolia ETH bridged to ZKsync Sepolia (chain 300).
Keep its key in an encrypted Foundry keystore. Never put it in a file in this repo.

With [foundry-zksync](https://github.com/matter-labs/foundry-zksync):

```bash
cast wallet import primeid-deployer --interactive      # prompts for the key, stores it encrypted
forge create contracts/PrimeIdRevocationRegistry.sol:PrimeIdRevocationRegistry \
  --zksync --rpc-url https://sepolia.era.zksync.dev --account primeid-deployer --broadcast
```

Put the printed address in `.env.local` as `VITE_PRIMEID_REGISTRY=0x...` and restart `npm run dev`.

Status: compiles with solc 0.8.24. It has not been deployed and not been tested on chain.
