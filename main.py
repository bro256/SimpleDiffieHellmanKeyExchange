import hmac
import logging
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# --- Key generation ---
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()
logging.info("Alice's key pair generated.")

bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()
logging.info("Bob's key pair generated.")

# --- ECDH exchange ---
# NOTE: This is the crux of why raw ECDH is not enough on its own.
# alice_public / bob_public are exchanged here with no signature, certificate,
# or prior-known fingerprint check. In a real network, an attacker could
# substitute their own key for either party's and neither side would notice.
# A real protocol would sign these keys with a long-term identity key,
# or verify them against a certificate/PKI, before ever using them.
alice_shared_secret = alice_private.exchange(bob_public)
bob_shared_secret = bob_private.exchange(alice_public)
logging.info("Shared secrets computed.")


def hkdf_extract(salt: bytes, input_key_material: bytes, hash_func=sha256) -> bytes:
    """RFC 5869 HKDF-Extract."""
    logging.debug("Performing HKDF-Extract.")
    return hmac.new(salt, input_key_material, hash_func).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func=sha256) -> bytes:
    """RFC 5869 HKDF-Expand."""
    logging.debug("Performing HKDF-Expand.")
    hash_len = hash_func().digest_size
    max_length = 255 * hash_len
    if length > max_length:
        raise ValueError(f"Requested length {length} exceeds HKDF max of {max_length} bytes")

    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_func).digest()
        okm += t
    return okm[:length]


def public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def derive_key_hkdf(
    shared_secret: bytes,
    party_a_pub: bytes,
    party_b_pub: bytes,
    salt: bytes = b"",
    length: int = 32,
) -> bytes:
    """
    Derive a symmetric key from a shared ECDH secret using HKDF.

    `info` is built from both parties' public keys (sorted so both sides
    compute the same bytes regardless of role) so the derived key is bound
    to this specific pair of keys/session rather than being a generic,
    reusable label.
    """
    logging.info("Deriving key using HKDF.")
    info = b"ecdh key" + b"".join(sorted([party_a_pub, party_b_pub]))
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, info, length)


alice_pub_bytes = public_bytes(alice_public)
bob_pub_bytes = public_bytes(bob_public)

alice_key = derive_key_hkdf(alice_shared_secret, alice_pub_bytes, bob_pub_bytes)
bob_key = derive_key_hkdf(bob_shared_secret, alice_pub_bytes, bob_pub_bytes)
logging.info("Keys derived for both Alice and Bob.")

print("Alice's derived key (SHA-256):", alice_key.hex())
print("Bob's derived key   (SHA-256):", bob_key.hex())

try:
    assert alice_key == bob_key, "ERROR: Alice and Bob keys do not match!"
    logging.info("SUCCESS: Shared key established successfully! (Still no authentication, though.)")
except AssertionError as e:
    logging.error(e)