import secrets
from hashlib import sha256


# Define public parameters for Diffie-Hellman
# Using RFC 3526 Group 14 (2048-bit MODP Group)
P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", "")

# Convert hex string to integer
P = int(P_HEX, 16)

# Generator: G = 2 (commonly used and safe for DH)
G = 2


# Alice generates her private and public keys
alice_private = secrets.randbelow(P - 2) + 2
alice_public = pow(G, alice_private, P)

# Bob generates his private and public keys
bob_private = secrets.randbelow(P - 2) + 2
bob_public = pow(G, bob_private, P)

# Alice and Bob compute the shared secret using each other's public keys
alice_shared_secret = pow(bob_public, alice_private, P)
bob_shared_secret = pow(alice_public, bob_private, P)

# Derive a key from the shared secret using SHA-256 hash function
def derive_key(shared_secret: int) -> bytes:
    return sha256(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')).digest()

alice_key = derive_key(alice_shared_secret)
bob_key = derive_key(bob_shared_secret)