#!/usr/bin/env python3
import argparse
import binascii
import getpass
import hashlib
import secrets
import struct
import sys
from pathlib import Path

ROUNDS_POWER = 24


def crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def _gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def _gf_pow(a, power):
    result = 1
    while power:
        if power & 1:
            result = _gf_mul(result, a)
        a = _gf_mul(a, a)
        power >>= 1
    return result


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sboxes():
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else _gf_pow(i, 254)
        value = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        value &= 0xFF
        sbox[i] = value
        inv_sbox[value] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _make_sboxes()


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


class AES256:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        expanded = self._expand_key(key)
        self.round_keys = [expanded[i:i + 16] for i in range(0, len(expanded), 16)]

    @staticmethod
    def _expand_key(key):
        expanded = bytearray(key)
        generated = len(expanded)
        rcon = 1

        while len(expanded) < 240:
            temp = list(expanded[-4:])
            if generated % 32 == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= rcon
                rcon = _gf_mul(rcon, 2)
            elif generated % 32 == 16:
                temp = [SBOX[b] for b in temp]

            for b in temp:
                expanded.append(expanded[generated - 32] ^ b)
                generated += 1

        return bytes(expanded)

    @staticmethod
    def _add_round_key(state, round_key):
        for i in range(16):
            state[i] ^= round_key[i]

    @staticmethod
    def _sub_bytes(state):
        for i, value in enumerate(state):
            state[i] = SBOX[value]

    @staticmethod
    def _shift_rows(state):
        old = state[:]
        state[:] = [
            old[0], old[5], old[10], old[15],
            old[4], old[9], old[14], old[3],
            old[8], old[13], old[2], old[7],
            old[12], old[1], old[6], old[11],
        ]

    @staticmethod
    def _mix_columns(state):
        for col in range(4):
            i = col * 4
            a0, a1, a2, a3 = state[i:i + 4]
            t = a0 ^ a1 ^ a2 ^ a3
            u = a0
            state[i] ^= t ^ _xtime(a0 ^ a1)
            state[i + 1] ^= t ^ _xtime(a1 ^ a2)
            state[i + 2] ^= t ^ _xtime(a2 ^ a3)
            state[i + 3] ^= t ^ _xtime(a3 ^ u)

    def encrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")

        state = list(block)
        self._add_round_key(state, self.round_keys[0])

        for round_number in range(1, 14):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[round_number])

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[14])
        return bytes(state)


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def aes256_cbc_encrypt(data, key, iv):
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")
    if len(data) % 16:
        raise ValueError("AES-CBC data must be block aligned")

    # 7z AES uses AES-CBC over complete 16-byte blocks. CBC security requires a
    # fresh unpredictable IV for each archive; build_archive generates it with
    # secrets.token_bytes and stores it in the 7z AES properties.
    aes = AES256(key)
    previous = iv
    out = []
    for offset in range(0, len(data), 16):
        block = xor_bytes(data[offset:offset + 16], previous)
        encrypted = aes.encrypt_block(block)
        out.append(encrypted)
        previous = encrypted
    return b"".join(out)


def encode_var64(n):
    if n < 0:
        raise ValueError("negative 7z integer")
    if n < 0x80:
        return bytes([n])
    if n < 2**16:
        return b"\xC0" + struct.pack("<H", n)
    if n < 2**32:
        return b"\xF0" + struct.pack("<L", n)
    return b"\xFF" + struct.pack("<Q", n)


def derive_7z_key(password, salt):
    password_bytes = password.encode("utf-16-le")
    digest = hashlib.sha256()
    for i in range(1 << ROUNDS_POWER):
        digest.update(salt)
        digest.update(password_bytes)
        digest.update(struct.pack("<Q", i))
    return digest.digest()


def zero_pad_to_block(data, minimum_size=0):
    block_size = 16
    padded_len = max(
        minimum_size,
        (len(data) + block_size - 1) & ~(block_size - 1),
    )
    padded_len = (padded_len + block_size - 1) & ~(block_size - 1)
    return data + (b"\x00" * (padded_len - len(data)))


def build_aes_properties(salt, iv):
    if len(salt) != 16 or len(iv) != 16:
        raise ValueError("7z AES salt and IV must be 16 bytes")
    return bytes([0xC0 | ROUNDS_POWER, 0xFF]) + salt + iv


def build_plain_header(plaintext, body_size, body_aes_props):
    trailer = bytes.fromhex("01 04 06 00 01 09")
    trailer += encode_var64(body_size)
    trailer += b"\x00"
    trailer += bytes.fromhex("07 0b 01 00 01 24 06 f1 07 01")

    trailer += encode_var64(len(body_aes_props))
    trailer += body_aes_props
    trailer += bytes.fromhex("01 00")
    trailer += b"\x0c" + encode_var64(len(plaintext)) + b"\x00"
    trailer += (
        bytes.fromhex("08 0a 01")
        + struct.pack("<L", crc32(plaintext))
        + b"\x00"
    )
    trailer += b"\x00"

    encoded_name = "backup.txt\x00".encode("utf-16-le")
    trailer += bytes.fromhex("05 01 11") + encode_var64(len(encoded_name) + 1)
    trailer += b"\x00" + encoded_name
    trailer += b"\x00\x00"
    return trailer


def build_encoded_header_info(
    pack_pos,
    packed_size,
    unpacked_size,
    header_crc,
    header_aes_props,
):
    header = b"\x17"
    header += b"\x06" + encode_var64(pack_pos) + encode_var64(1)
    header += b"\x09" + encode_var64(packed_size) + b"\x00"
    header += bytes.fromhex("07 0b 01 00 01 24 06 f1 07 01")
    header += encode_var64(len(header_aes_props)) + header_aes_props
    header += b"\x0c" + encode_var64(unpacked_size)
    header += b"\x0a\x01" + struct.pack("<L", header_crc)
    header += b"\x00\x00"
    return header


def build_archive(plaintext, password):
    body_salt = secrets.token_bytes(16)
    body_iv = secrets.token_bytes(16)
    body_key = derive_7z_key(password, body_salt)

    padded = zero_pad_to_block(plaintext, 1024)
    body = aes256_cbc_encrypt(padded, body_key, body_iv)

    body_props = build_aes_properties(body_salt, body_iv)
    plain_header = build_plain_header(plaintext, len(body), body_props)

    header_salt = secrets.token_bytes(16)
    header_iv = secrets.token_bytes(16)
    header_key = derive_7z_key(password, header_salt)
    encrypted_header = aes256_cbc_encrypt(
        zero_pad_to_block(plain_header),
        header_key,
        header_iv,
    )
    header_props = build_aes_properties(header_salt, header_iv)
    encoded_header = build_encoded_header_info(
        len(body),
        len(encrypted_header),
        len(plain_header),
        crc32(plain_header),
        header_props,
    )

    next_header_offset = len(body) + len(encrypted_header)
    section_header = struct.pack(
        "<QQL",
        next_header_offset,
        len(encoded_header),
        crc32(encoded_header),
    )
    file_header = b"7z\xbc\xaf'\x1c" + struct.pack(
        "<BBL",
        0,
        4,
        crc32(section_header),
    )
    return file_header + section_header + body + encrypted_header + encoded_header

def get_mnemonic():
    mnemonic_text = input("Mnemonic words: ")
    mnemonic_words = [
        word.strip().lower()
        for word in mnemonic_text.split()
        if word.strip()
    ]
    if len(mnemonic_words) not in (12, 24):
        raise ValueError("mnemonic must contain exactly 12 or 24 words")

    wordlist_path = Path(__file__).resolve().with_name("bip39-eng.txt")
    try:
        wordlist_words = [
            line.strip()
            for line in wordlist_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except OSError as exc:
        raise ValueError(f"cannot read {wordlist_path}: {exc}") from exc

    if len(wordlist_words) != 2048:
        raise ValueError(f"{wordlist_path} must contain exactly 2048 words")

    wordlist = set(wordlist_words)
    unknown = [word for word in mnemonic_words if word not in wordlist]
    if unknown:
        raise ValueError("unknown BIP39 word: " + unknown[0])

    mnemonic = " ".join(mnemonic_words)
    return mnemonic

def get_pw():
    passphrase = getpass.getpass("Archive passphrase: ")
    passphrase_confirm = getpass.getpass("Confirm archive passphrase: ")
    if passphrase != passphrase_confirm:
        raise ValueError("archive passphrases do not match")
    if not passphrase:
        raise ValueError("archive passphrase must not be empty")
    return passphrase

def main(argv=None):
    try:
        parser = argparse.ArgumentParser(
            description="Create a minimal encrypted 7z backup containing backup.txt."
        )
        parser.add_argument("archive", help="output archive path")
        args = parser.parse_args(argv)
        mnemonic = get_mnemonic()
        passphrase = get_pw()
        nonce = secrets.token_hex(32)
        plaintext = (
            f"# Generated by bip39tools/encrypt_backup.py. Nonce: {nonce}\n"
            f'mnemonic = "{mnemonic}"\n'
        ).encode("utf-8")
        archive = build_archive(plaintext, passphrase)
        Path(args.archive).write_bytes(archive)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
