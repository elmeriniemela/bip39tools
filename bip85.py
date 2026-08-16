#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import struct
import unicodedata
from pathlib import Path

HARDENED = 0x80000000
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
WORD_COUNT_BYTES = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}

wordfilepath = Path(__file__).with_name("bip39-eng.txt")
assert wordfilepath.exists(), f"Download https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt into {wordfilepath.resolve()}"
WORDS = wordfilepath.read_text(encoding="ascii").split()
assert len(WORDS) == 2048, f"{wordfilepath} must contain exactly 2048 words, found {len(WORDS)}."
assert WORDS[0] == "abandon", "First word must be abandon"
assert WORDS[2047] == "zoo", "Last word must be zoo"
WORD_INDEX = {word: index for index, word in enumerate(WORDS)}


def entropy_to_mnemonic(entropy):
    bits = "".join(f"{byte:08b}" for byte in entropy)
    bits += "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())[: len(entropy) * 8 // 32]
    return " ".join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def bip85_entropy(root_key, chain_code, word_count, index):
    if word_count not in WORD_COUNT_BYTES:
        raise ValueError("word_count must be one of 12, 15, 18, 21, 24")
    if not 0 <= index < HARDENED:
        raise ValueError("index must be between 0 and 2147483647")
    if len(root_key) != 32 or len(chain_code) != 32 or not 0 < int.from_bytes(root_key, "big") < SECP256K1_N:
        raise ValueError("invalid BIP32 root key")

    key, chain = root_key, chain_code
    for child in (83696968, 39, 0, word_count, index):
        digest = hmac.new(chain, b"\0" + key + struct.pack(">L", child | HARDENED), hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        child_key = (tweak + int.from_bytes(key, "big")) % SECP256K1_N
        if tweak >= SECP256K1_N or child_key == 0:
            raise ValueError("invalid BIP32 child key")
        key, chain = child_key.to_bytes(32, "big"), digest[32:]

    return hmac.new(b"bip-entropy-from-k", key, hashlib.sha512).digest()[:WORD_COUNT_BYTES[word_count]]


def bip85_from_mnemonic(mnemonic, word_count, index):
    words = mnemonic.lower().split()
    if len(words) not in WORD_COUNT_BYTES:
        raise ValueError("parent mnemonic must have 12, 15, 18, 21, or 24 words")
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
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), b"mnemonic", 2048)
    root = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return entropy_to_mnemonic(bip85_entropy(root[:32], root[32:], word_count, index))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("word_count", type=int, choices=sorted(WORD_COUNT_BYTES))
    parser.add_argument("index", type=int, help="BIP85 child index")
    args = parser.parse_args()
    derivation_path = f"m/83696968'/39'/0'/{args.word_count}'/{args.index}'"
    mnemonic = input(f"Derive {derivation_path} from mnemonic: ")
    try:
        print(bip85_from_mnemonic(mnemonic, args.word_count, args.index))
    except ValueError as e:
        raise SystemExit(str(e))


if __name__ == "__main__":
    main()
