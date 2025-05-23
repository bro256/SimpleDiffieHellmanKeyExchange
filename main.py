import hmac
import logging
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import x25519

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Alice generates her private and public keys
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()
logging.info("Alice's key pair generated.")

# Bob generates his private and public keys
bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()
logging.info("Bob's key pair generated.")

# Alice and Bob compute the shared secret
alice_shared_secret = alice_private.exchange(bob_public)
bob_shared_secret = bob_private.exchange(alice_public)
logging.info("Shared secrets computed.")

# HKDF-Extract step: Uses a salt and the input key material (shared secret) 
def hkdf_extract(salt: bytes, input_key_material: bytes, hash_func=sha256) -> bytes:
    """
    Perform the HKDF-Extract step.
    
    Args:
        salt (bytes): A non-secret random value (can be empty).
        input_key_material (bytes): The shared secret from ECDH.
        hash_func (Callable): The hash function to use (default: sha256).

    Returns:
        bytes: A pseudorandom key (PRK).
    """
    logging.debug("Performing HKDF-Extract.")
    return hmac.new(salt, input_key_material, hash_func).digest()

# HKDF-Expand step: Expands the PRK into output key material (OKM) of the desired length.
# The 'info' parameter allows context-specific key derivation.
def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func=sha256) -> bytes:
    """
    Perform the HKDF-Expand step to derive key material.

    Args:
        prk (bytes): Pseudorandom key from HKDF-Extract.
        info (bytes): Context/application-specific information (optional).
        length (int): Desired length of output keying material in bytes.
        hash_func (Callable): The hash function to use (default: sha256).

    Returns:
        bytes: Output keying material (OKM).
    """
    logging.debug("Performing HKDF-Expand.")
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
    """
    Derive a symmetric key from a shared ECDH secret using HKDF.

    Args:
        shared_secret (bytes): The shared ECDH secret.
        salt (bytes, optional): A non-secret random value (default: b"").
        info (bytes, optional): Context/application-specific information (default: b"ecdh key").
        length (int, optional): Length of the derived key in bytes (default: 32).

    Returns:
        bytes: The derived symmetric key.
    """
    logging.info("Deriving key using HKDF.")
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, info, length)

# Derive keys
alice_key = derive_key_hkdf(alice_shared_secret)
bob_key = derive_key_hkdf(bob_shared_secret)
logging.info("Keys derived for both Alice and Bob.")

# Print both derived keys
print("Alice's derived key (SHA-256):", alice_key.hex())
print("Bob's derived key   (SHA-256):", bob_key.hex())

# Verify that both sides computed the same shared secret
try:
    assert alice_key == bob_key, "ERROR: Alice and Bob keys do not match!"
    logging.info("SUCCESS: Shared key established successfully!")
except AssertionError as e:
    logging.error(e)
