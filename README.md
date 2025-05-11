# SimpleDiffieHellmanKeyExchange

A Python implementation of the Diffie-Hellman key exchange protocol utilizing the 2048-bit MODP prime group as defined in RFC 3526, Group 14. This simulation generates secure random private keys for both parties using Python's secrets module and computes their corresponding public keys via modular exponentiation. The shared secret is derived by each party through the other's public key and their own private key, followed by the application of the SHA-256 cryptographic hash function to generate a symmetric encryption key. The system performs a verification step to ensure both parties compute identical shared keys, confirming the integrity of the exchange.

This implementation is designed for those looking to learn cryptography and understand the core principles of key exchange protocols.
