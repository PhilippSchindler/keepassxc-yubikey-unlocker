"""
Various cryptography related functions.
"""

import hashlib


def derive_seed(passphrase: str) -> bytes:
    """Uses SHA3-256 to derives a cryptographic seed from a given password."""
    return hashlib.sha3_256(passphrase.encode()).digest()


def derive_pin(seed: bytes, serial: int) -> str:
    """Given a 32 byte seed, derive a 8 byte long pin code. Due to firmware limitation, ensuring compatibility, only
    the range 0x00 to 0x79 are allowed value. Still the PINs provide 56 bit of entropy.
    """
    assert len(seed) == 32
    hasher = hashlib.sha3_256(seed)
    hasher.update(f"pin(serial={serial})".encode())
    pin_bytes = bytes(byte & 0b0111_1111 for byte in hasher.digest()[:8])
    return pin_bytes.decode()


def derive_challenge(seed: bytes, serial: int) -> bytes:
    """Given a 32 byte seed, derive a 32 byte challenge."""
    assert len(seed) == 32
    hasher = hashlib.sha3_256(seed)
    hasher.update(f"challenge(serial={serial})".encode())
    return hasher.digest()


def rsa_pad_message(message: bytes, padded_length_in_bytes: int) -> bytes:
    """Implements EMSA-PKCS1-v1_5 message padding for RSA signing. SHA2-256 is selected as hash function.
    See: https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
    """
    digest = hashlib.sha256(message).digest()
    digest_info = bytes.fromhex("30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20") + digest

    if padded_length_in_bytes < len(digest_info) + 11:
        raise ValueError("Intended message length too short.")

    PS = b"\xff" * (padded_length_in_bytes - len(digest_info) - 3)
    padded_message = b"\x00" + b"\x01" + PS + b"\x00" + digest_info
    assert len(padded_message) == padded_length_in_bytes
    return padded_message


def xor_bytes(aa: bytes, bb: bytes) -> bytes:
    """Compute the binary XOR of two byte sequences of equal length."""
    if len(aa) != len(bb):
        raise ValueError("Input sequences must be of equal length.")
    return bytes(a ^ b for a, b in zip(aa, bb))
