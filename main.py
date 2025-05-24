import hmac
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import x25519

# Alice generates her private and public keys
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# Bob generates his private and public keys
bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# Alice and Bob compute the shared secret
alice_shared_secret = alice_private.exchange(bob_public)
bob_shared_secret = bob_private.exchange(alice_public)

# HKDF-Extract step: Uses a salt and the input key material (shared secret) 
def hkdf_extract(salt: bytes, input_key_material: bytes, hash_func=sha256) -> bytes:
    return hmac.new(salt, input_key_material, hash_func).digest()

# HKDF-Expand step: Expands the PRK into output key material (OKM) of the desired length.
def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func=sha256) -> bytes:
    hash_len = hash_func().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_func).digest()
        okm += t
    return okm[:length]

# Main key derivation function using HKDF (extract + expand)
def derive_key_hkdf(shared_secret: bytes, salt: bytes = b"", info: bytes = b"ecdh key", length: int = 32) -> bytes:
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, info, length)

# Derive keys
alice_key = derive_key_hkdf(alice_shared_secret)
bob_key = derive_key_hkdf(bob_shared_secret)
# Print both derived keys
print("Alice's derived key (SHA-256):", alice_key.hex())
print("Bob's derived key   (SHA-256):", bob_key.hex())

# Verify that both sides computed the same shared secret
assert alice_key == bob_key, "ERROR: Alice and Bob keys do not match!"
print("SUCCESS: Shared key established successfully!")
