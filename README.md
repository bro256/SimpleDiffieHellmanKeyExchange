# SimpleDiffieHellmanKeyExchange

Python implementation of X25519 elliptic-curve Diffie-Hellman (ECDH) key exchange with HKDF-SHA256 key derivation, for educational purposes only.

**Not production-ready.** This demonstrates the math of key agreement and key derivation - it does not implement a secure protocol. In particular:
- **No authentication:** nothing verifies that a public key actually belongs to the party who claims to own it. A real attacker sitting between Alice and Bob can swap in their own public keys and silently man-in-the-middle the whole exchange - ECDH's math offers zero protection against this by itself. Real-world protocols always pair ECDH with signatures, certificates, or pre-shared identity keys to bind public keys to identities.
- **No identity or transcript binding.** The derived keys are bound to the two exchanged public keys via the HKDF context, but not to verified identities or a full handshake transcript - so key derivation alone still cannot detect a substituted key or a tampered handshake.
- **No replay or freshness guarantees** - there's no nonce/session ID exchanged, so this alone can't detect a replayed handshake.

Use this to learn how ECDH + HKDF work mechanically. Don't use it as a template for anything that needs to resist an active attacker.
