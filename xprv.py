#!/usr/bin/env python3
"""Derive a mainnet BIP32 root extended private key from BIP39 words."""

import hashlib
import hmac
import unicodedata
from pathlib import Path


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
WORD_COUNTS = (12, 15, 18, 21, 24)

wordfilepath = Path(__file__).with_name("bip39-eng.txt")
assert wordfilepath.exists(), f"Download https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt into {wordfilepath.resolve()}"
WORDS = wordfilepath.read_text(encoding="ascii").split()
assert len(WORDS) == 2048, f"{wordfilepath} must contain exactly 2048 words, found {len(WORDS)}."
assert WORDS[0] == "abandon", "First word must be abandon"
assert WORDS[2047] == "zoo", "Last word must be zoo"
WORD_INDEX = {word: index for index, word in enumerate(WORDS)}


def seed_from_mnemonic(mnemonic, passphrase=""):
    """Validate an English BIP39 mnemonic and derive its 64-byte seed."""
    words = mnemonic.lower().split()
    if len(words) not in WORD_COUNTS:
        raise ValueError("mnemonic must have 12, 15, 18, 21, or 24 words")
    try:
        numbers = [WORD_INDEX[word] for word in words]
    except KeyError as e:
        raise ValueError(f"unknown BIP39 word: {e.args[0]}") from None

    bits = "".join(f"{number:011b}" for number in numbers)
    entropy_bits = bits[: len(bits) * 32 // 33]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    checksum = "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())[: len(entropy) * 8 // 32]
    if bits[len(entropy_bits):] != checksum:
        raise ValueError("invalid BIP39 checksum")

    phrase = unicodedata.normalize("NFKD", " ".join(words))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt.encode("utf-8"), 2048)
    return seed


def xprv_from_seed(seed):
    """Derive a mainnet BIP32 root extended private key from seed bytes."""
    root = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    if not 0 < int.from_bytes(root[:32], "big") < SECP256K1_N:
        raise ValueError("invalid BIP32 root key")

    payload = b"\x04\x88\xad\xe4" + b"\0" * 9 + root[32:] + b"\0" + root[:32]
    encoded = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(encoded, "big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    xprv = ""
    while value:
        value, digit = divmod(value, 58)
        xprv = alphabet[digit] + xprv
    return xprv


def main():
    mnemonic = input("Derive root xprv from mnemonic: ")
    try:
        print(xprv_from_seed(seed_from_mnemonic(mnemonic)))
    except ValueError as e:
        raise SystemExit(str(e))


if __name__ == "__main__":
    main()
