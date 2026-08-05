#!/usr/bin/env python3
"""
Verify COLDCARD dice-roll seed words.

Usage:
    ./cc-dice.py -n 24 123456...
    printf '%s\n' 123456... | ./cc-dice.py -n 12

Adapted from the COLDCARD firmware repository:
    coldcard-firmware/docs/rolls.py
    coldcard-firmware/docs/rolls12.py

The dice hashing flow matches:
    coldcard-firmware/shared/seed.py:add_dice_rolls
    coldcard-firmware/shared/seed.py:new_from_dice
"""

import argparse
import hashlib
from pathlib import Path
import re


wordfilepath = Path(__file__).with_name("bip39-eng.txt")
assert wordfilepath.exists(), f"Download https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt into {wordfilepath.resolve()}"
WL = wordfilepath.read_text(encoding="ascii").split()
assert len(WL) == 2048, f"{WL} must contain exactly 2048 words, found {len(words)}."
assert WL[0] == 'abandon', 'First word must be abandon'
assert WL[2047] == 'zoo', 'Last word must be zoo'


def entropy_to_mnemonic24(entropy):
    # 24-word seeds use 32 selected entropy bytes, or 256 bits.
    assert len(entropy) == 32
    # interpret entropy as big-endian bits and reserve 8 low bits
    # for the BIP39 checksum.
    value = int.from_bytes(entropy, "big") << 8
    indexes = []
    # split entropy || checksum placeholder into 24 11-bit groups.
    for _ in range(24):
        value, index = divmod(value, 2048)
        indexes.insert(0, index)
    assert value == 0
    # compute the checksum from the selected entropy bytes, not
    # from the original dice-roll digest. The low 8 placeholder bits are zero,
    # so OR appends the first checksum byte to the final group.
    indexes[-1] |= hashlib.sha256(entropy).digest()[0]
    # use each 11-bit group as a zero-based BIP39 wordlist index.
    return [WL[index] for index in indexes]


def entropy_to_mnemonic12(entropy):
    # 12-word seeds use 16 selected entropy bytes, or 128 bits.
    assert len(entropy) == 16
    # interpret entropy as big-endian bits and reserve 4 low bits
    # for the BIP39 checksum.
    value = int.from_bytes(entropy, "big") << 4
    indexes = []
    # split entropy || checksum placeholder into 12 11-bit groups.
    for _ in range(12):
        value, index = divmod(value, 2048)
        indexes.insert(0, index)
    assert value == 0
    # compute the checksum from the selected entropy bytes, not
    # from the original dice-roll digest. The low 4 placeholder bits are zero,
    # so adding the high checksum nibble appends it to the final group.
    indexes[-1] += hashlib.sha256(entropy).digest()[0] >> 4
    # use each 11-bit group as a zero-based BIP39 wordlist index.
    return [WL[index] for index in indexes]


def mnemonic_from_dice(rolls):
    entropy = hashlib.sha256(rolls.encode("ascii")).digest()
    if len(rolls) == 50:
        return entropy_to_mnemonic12(entropy[:16])
    elif len(rolls) == 99:
        return entropy_to_mnemonic24(entropy)
    raise ValueError(f"Invalid amount of rolls: {len(rolls)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--words", type=int, choices=(12, 24), default=24)
    parser.add_argument("rolls", nargs="?", help="dice rolls, using digits 1 through 6")
    args = parser.parse_args()

    rolls = args.rolls

    if not rolls:
        raise SystemExit("No dice rolls provided.")
    # after whitespace removal, only dice face digits are valid.
    if re.search(r"[^1-6]", rolls):
        raise SystemExit("Dice rolls must contain only digits 1 through 6.")

    # COLDCARD hashes every provided roll as ASCII text.
    entropy = hashlib.sha256(rolls.encode("ascii")).digest()

    if args.words == 12:
        # 12-word seeds use the first 16 digest bytes.
        words = entropy_to_mnemonic12(entropy[:16])
        min_rolls = 50
        shown_entropy = entropy[:16]
    else:
        # 24-word seeds use all 32 digest bytes.
        words = entropy_to_mnemonic24(entropy)
        min_rolls = 99
        shown_entropy = entropy

    # COLDCARD accepts at least the minimum roll count for the
    # requested seed length, hashing every roll provided.
    if len(rolls) < min_rolls:
        raise SystemExit(f"warning: COLDCARD requires at least {min_rolls} rolls for {args.words} words")

    # join the selected BIP39 words with spaces.
    jwords = ' '.join(words)
    print(f"{jwords} / rolls: {len(rolls)} / entropy: {shown_entropy.hex()}")


if __name__ == "__main__":
    main()
