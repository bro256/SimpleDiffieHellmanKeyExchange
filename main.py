import secrets
import hmac
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

# Print public parameters
print("Public Parameters:")
print(f"P (2048-bit prime): {hex(P)}")
print(f"G (generator): {G}\n")

# Alice generates her private and public keys
alice_private = secrets.randbelow(P - 2) + 2
alice_public = pow(G, alice_private, P)

# Bob generates his private and public keys
bob_private = secrets.randbelow(P - 2) + 2
bob_public = pow(G, bob_private, P)

# Alice and Bob compute the shared secret using each other's public keys
alice_shared_secret = pow(bob_public, alice_private, P)
bob_shared_secret = pow(alice_public, bob_private, P)

# HKDF-Extract step: Uses a salt and the input key material (shared secret) 
# to create a pseudorandom key (PRK) using HMAC-SHA256.
def hkdf_extract(salt: bytes, input_key_material: bytes, hash_func=sha256) -> bytes:
    return hmac.new(salt, input_key_material, hash_func).digest()

# HKDF-Expand step: Expands the PRK into output key material (OKM) of the desired length.
# The 'info' parameter allows context-specific key derivation (e.g., "encryption", "auth").
def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func=sha256) -> bytes:
    hash_len = hash_func().digest_size
    n = (length + hash_len - 1) // hash_len  # Number of hash blocks needed
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_func).digest()
        okm += t
    return okm[:length]

# Main key derivation function using HKDF (extract + expand).
# Converts the shared integer secret to bytes, performs extract and expand,
# and returns a key of the requested length (default 32 bytes = 256 bits).
def derive_key_hkdf(shared_secret: int, salt: bytes = b"", info: bytes = b"dh key", length: int = 32) -> bytes:
    shared_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    prk = hkdf_extract(salt, shared_bytes)
    return hkdf_expand(prk, info, length)

alice_key = derive_key_hkdf(alice_shared_secret)
bob_key = derive_key_hkdf(bob_shared_secret)

# Print both derived keys
print("Alice's derived key (SHA-256):", alice_key.hex())
print("Bob's derived key   (SHA-256):", bob_key.hex())

# Verify that both sides computed the same shared secret
assert alice_key == bob_key, "❌ ERROR: Alice and Bob keys do not match!"
print("✅ SUCCESS: Shared key established successfully!")
