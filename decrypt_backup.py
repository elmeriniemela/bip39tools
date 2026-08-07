#!/usr/bin/env python3
import argparse
import binascii
import getpass
import hashlib
import io
import struct
import sys
from pathlib import Path


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


def _gf_mul_many(a0, a1, a2, a3):
    return (
        _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9),
        _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13),
        _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11),
        _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14),
    )


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
    def _inv_sub_bytes(state):
        for i, value in enumerate(state):
            state[i] = INV_SBOX[value]

    @staticmethod
    def _inv_shift_rows(state):
        old = state[:]
        state[:] = [
            old[0], old[13], old[10], old[7],
            old[4], old[1], old[14], old[11],
            old[8], old[5], old[2], old[15],
            old[12], old[9], old[6], old[3],
        ]

    @staticmethod
    def _inv_mix_columns(state):
        for col in range(4):
            i = col * 4
            state[i], state[i + 1], state[i + 2], state[i + 3] = _gf_mul_many(*state[i:i + 4])

    def decrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")

        state = list(block)
        self._add_round_key(state, self.round_keys[14])

        for round_number in range(13, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self.round_keys[round_number])
            self._inv_mix_columns(state)

        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self.round_keys[0])
        return bytes(state)


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def aes256_cbc_decrypt(data, key, iv):
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")
    if len(data) % 16:
        raise ValueError("AES-CBC data must be block aligned")

    aes = AES256(key)
    previous = iv
    out = []
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        decrypted = aes.decrypt_block(block)
        out.append(xor_bytes(decrypted, previous))
        previous = block
    return b"".join(out)


def read_var64(stream):
    first_raw = stream.read(1)
    if not first_raw:
        raise ValueError("truncated 7z integer")
    first = first_raw[0]

    if first < 0x80:
        return first
    if first in (0xFE, 0xFF):
        raw = stream.read(8)
        if len(raw) != 8:
            raise ValueError("truncated 7z integer")
        return struct.unpack("<Q", raw)[0]

    bits = bin(first)[2:].rjust(8, "0")
    extra = bits.find("10") + 1
    if not 1 <= extra <= 6:
        raise ValueError("invalid 7z integer")
    raw = stream.read(extra)
    if len(raw) != extra:
        raise ValueError("truncated 7z integer")
    y = struct.unpack("<Q", raw + (b"\x00" * (8 - extra)))[0]
    x = first & (0xEF >> extra)
    return (x << extra) + y


def read_var64_at(data, offset):
    stream = io.BytesIO(data[offset:])
    value = read_var64(stream)
    return value, offset + stream.tell()


def require_find(data, pattern, start=0):
    offset = data.find(pattern, start)
    if offset < 0:
        raise ValueError("unsupported 7z archive layout")
    return offset + len(pattern)


def read_aes_properties(header, start):
    single_aes = bytes.fromhex("07 0b 01 00 01 24 06 f1 07 01")
    copy_aes = bytes.fromhex("07 0b 01 00 02 24 06 f1 07 01")
    matches = [
        (offset, pattern)
        for pattern in (single_aes, copy_aes)
        for offset in [header.find(pattern, start)]
        if offset >= 0
    ]
    if not matches:
        raise ValueError("unsupported 7z archive layout")

    offset, pattern = min(matches)
    offset += len(pattern)
    props_len, offset = read_var64_at(header, offset)
    props = header[offset:offset + props_len]
    if len(props) != props_len or len(props) < 2:
        raise ValueError("truncated 7z AES properties")

    props_end = offset + props_len
    if pattern == copy_aes and header[props_end:props_end + 4] != bytes.fromhex("01 00 01 00"):
        raise ValueError("unsupported 7z archive layout")

    return props, props_end, 2 if pattern == copy_aes else 1


def parse_aes_properties(props):
    first, second = props[0], props[1]
    if (first & 0xC0) == 0:
        raise ValueError("7z AES properties must include salt or IV metadata")
    rounds_power = first & 0x3F

    prop_offset = 2
    salt_len = ((first >> 7) & 1) + (second >> 4)
    iv_len = ((first >> 6) & 1) + (second & 0xF)
    salt = props[prop_offset:prop_offset + salt_len]
    prop_offset += salt_len
    iv = props[prop_offset:prop_offset + iv_len]
    prop_offset += iv_len
    if len(salt) != salt_len or len(iv) != iv_len or prop_offset != len(props):
        raise ValueError("invalid 7z AES properties")
    if len(salt) > 16 or len(iv) > 16:
        raise ValueError("invalid 7z AES properties")

    return rounds_power, salt, iv + (b"\x00" * (16 - len(iv)))


def read_file_name(header, start):
    offset = require_find(header, bytes.fromhex("05 01"), start)
    while offset < len(header):
        prop_id = header[offset]
        offset += 1
        if prop_id == 0:
            break

        prop_len, offset = read_var64_at(header, offset)
        prop = header[offset:offset + prop_len]
        if len(prop) != prop_len:
            raise ValueError("truncated 7z file property")
        offset += prop_len

        if prop_id == 0x11:
            if prop_len < 1 or prop[0] != 0:
                raise ValueError("invalid 7z file name")
            return prop[1:].decode("utf-16-le").removesuffix("\x00")

    raise ValueError("invalid 7z file name")


def decrypt_encoded_header(header, streams, password):
    if not header or header[0] != 0x17:
        return header, None

    offset = 1
    if offset >= len(header) or header[offset] != 0x06:
        raise ValueError("unsupported 7z encoded header")
    offset += 1

    pack_pos, offset = read_var64_at(header, offset)
    num_pack_streams, offset = read_var64_at(header, offset)
    if num_pack_streams != 1:
        raise ValueError("unsupported 7z encoded header")

    if offset >= len(header) or header[offset] != 0x09:
        raise ValueError("unsupported 7z encoded header")
    offset += 1
    packed_size, offset = read_var64_at(header, offset)
    if offset >= len(header) or header[offset] != 0:
        raise ValueError("invalid 7z encoded header pack info")
    offset += 1

    props, offset, unpacked_size_count = read_aes_properties(header, offset)
    if unpacked_size_count != 1:
        raise ValueError("unsupported 7z encoded header")
    rounds_power, salt, iv = parse_aes_properties(props)

    if offset >= len(header) or header[offset] != 0x0c:
        raise ValueError("invalid 7z encoded header unpack size")
    offset += 1
    unpacked_size, offset = read_var64_at(header, offset)

    if offset + 6 > len(header) or header[offset:offset + 2] != b"\x0a\x01":
        raise ValueError("invalid 7z encoded header CRC")
    expected_crc = struct.unpack_from("<L", header, offset + 2)[0]
    offset += 6
    if offset + 2 > len(header) or header[offset:offset + 2] != b"\x00\x00":
        raise ValueError("invalid 7z encoded header terminator")

    encrypted_header = streams[pack_pos:pack_pos + packed_size]
    if len(encrypted_header) != packed_size:
        raise ValueError("truncated 7z encoded header")

    key = derive_7z_key(password, salt, rounds_power)
    padded_header = aes256_cbc_decrypt(encrypted_header, key, iv)
    if unpacked_size > len(padded_header):
        raise ValueError("invalid 7z encoded header size")
    decoded_header = padded_header[:unpacked_size]

    if crc32(decoded_header) != expected_crc:
        raise ValueError("wrong password or damaged archive")

    return decoded_header, pack_pos


def derive_7z_key(password, salt, rounds_power):
    password_bytes = password.encode("utf-16-le")
    digest = hashlib.sha256()
    for i in range(1 << rounds_power):
        digest.update(salt)
        digest.update(password_bytes)
        digest.update(struct.pack("<Q", i))
    return digest.digest()


def decrypt_archive(data, password):
    if len(data) < 32:
        raise ValueError("archive is too small")

    magic, major, minor, next_header_crc = struct.unpack("<6sBBL", data[:12])
    if magic != b"7z\xbc\xaf'\x1c" or major != 0 or minor < 3:
        raise ValueError("bad 7z magic or version")

    section_header = data[12:32]
    if crc32(section_header) != next_header_crc:
        raise ValueError("7z section header CRC mismatch")

    body_offset, header_size, header_crc = struct.unpack("<QQL", section_header)
    header_start = 32 + body_offset
    header_end = header_start + header_size
    if header_end > len(data):
        raise ValueError("truncated archive")

    streams = data[32:header_start]
    header = data[header_start:header_end]
    if crc32(header) != header_crc:
        raise ValueError("7z trailing header CRC mismatch")

    header, encoded_header_start = decrypt_encoded_header(header, streams, password)

    offset = require_find(header, bytes.fromhex("01 04 06 00 01 09"))
    body_size, offset = read_var64_at(header, offset)
    if body_size > len(streams):
        raise ValueError("7z packed size mismatch")
    if encoded_header_start is None:
        if len(streams) != body_size:
            raise ValueError("7z packed size mismatch")
    elif encoded_header_start != body_size:
        raise ValueError("unsupported 7z archive layout")
    body = streams[:body_size]

    props, offset, unpacked_size_count = read_aes_properties(header, offset)
    rounds_power, salt, iv = parse_aes_properties(props)

    offset = require_find(header, bytes.fromhex("01 00 0c"), offset)
    unpacked_sizes = []
    for _ in range(unpacked_size_count):
        unpacked_size, offset = read_var64_at(header, offset)
        unpacked_sizes.append(unpacked_size)
    if offset >= len(header) or header[offset] != 0:
        raise ValueError("invalid 7z unpacked size")
    offset += 1
    unpacked_size = unpacked_sizes[-1]

    offset = require_find(header, bytes.fromhex("08 0a 01"), offset)
    if offset + 5 > len(header):
        raise ValueError("truncated 7z CRC")
    expected_crc = struct.unpack_from("<L", header, offset)[0]
    offset += 4
    if header[offset] != 0:
        raise ValueError("invalid 7z CRC field")
    offset += 1

    filename = read_file_name(header, offset)

    key = derive_7z_key(password, salt, rounds_power)
    plaintext_padded = aes256_cbc_decrypt(body, key, iv)
    if unpacked_size > len(plaintext_padded):
        raise ValueError("invalid 7z unpacked size")
    plaintext = plaintext_padded[:unpacked_size]

    if crc32(plaintext) != expected_crc:
        raise ValueError("wrong password or damaged archive")

    return filename, plaintext


def main(argv=None):
    try:
        parser = argparse.ArgumentParser(
            description="Decrypt a minimal 7z AES backup and print its single file."
        )
        parser.add_argument("archive", help="archive path")
        args = parser.parse_args(argv)

        password = getpass.getpass("Archive passphrase: ")
        if not password:
            raise ValueError("archive passphrase must not be empty")

        archive_path = Path(args.archive)
        _, plaintext = decrypt_archive(archive_path.read_bytes(), password)
        sys.stdout.buffer.write(plaintext)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
