#!/usr/bin/env python3
"""Turn dicerolls into a BIP-39 mnemonic

Usage:
    ./dice.py 24 123456...

Inspiration/source references:
- seedsigner/src/seedsigner/helpers/mnemonic_generation.py
- seedsigner/tools/mnemonic.py
- seedsigner/tests/test_mnemonic_generation.py
- seedsigner/docs/dice_verification.md
- src/bip39-eng.txt for the English BIP39 wordlist

Spec step references in comments point to docs/README.md section 6.
"""

import argparse
import hashlib
from pathlib import Path
import re

wordfilepath = Path(__file__).with_name("bip39-eng.txt")
assert wordfilepath.exists(), f"Download https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt into {wordfilepath.resolve()}"
WORDLIST = wordfilepath.read_text(encoding="ascii").split()
assert len(WORDLIST) == 2048, f"{WORDLIST} must contain exactly 2048 words, found {len(words)}."
assert WORDLIST[0] == 'abandon', 'First word must be abandon'
assert WORDLIST[2047] == 'zoo', 'Last word must be zoo'

def mnemonic_from_dice(rolls):
    # Hash the dice-roll digits as ASCII text, then use normal BIP39 encoding
    # (Spec 1, Spec 3).
    entropy = hashlib.sha256(rolls.encode("ascii")).digest()
    # Select the entropy bytes from the dice-roll digest (Spec 4):
    # 50-roll / 12-word seeds use the first 16 digest bytes, while the CLI
    # validation below leaves 99-roll / 24-word seeds as all 32 bytes.
    if len(rolls) == 50:
        entropy = entropy[:16]
        # BIP39 checksum length is ENT / 32: 4 bits for 128-bit entropy, 8 bits for
        # 256-bit entropy (Spec 5).
        checksum_len = 4
    else:
        checksum_len = 8

    # Write the selected entropy bytes as a big-endian bit string, most
    # significant bit first for each byte (Spec 6).
    entropy_bits = "".join(f"{byte:08b}" for byte in entropy)
    # Compute the checksum from the selected entropy bytes, not from the
    # original dice-roll digest (Spec 5).
    checksum_bits = "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())[:checksum_len]
    bits = entropy_bits + checksum_bits
    # Split entropy || checksum into 11-bit groups, interpret each group as an
    # integer, and use it as a BIP39 wordlist index (Spec 7, Spec 8, Spec 9).
    words = [WORDLIST[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11)]

    # Join the selected BIP39 words with spaces (Spec 10).
    return words

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("words", type=int, choices=(12, 24))
    parser.add_argument("rolls", help="dice rolls, using digits 1 through 6")
    args = parser.parse_args()

    rolls = args.rolls

    # Only dice face digits are valid for this CLI argument (Spec 1).
    if re.search(r"[^1-6]", rolls):
        raise SystemExit("Dice rolls must contain only digits 1 through 6.")

    expected_rolls = 50 if args.words == 12 else 99
    if len(rolls) != expected_rolls:
        raise SystemExit(f"Exactly {expected_rolls} rolls required for {args.words} words.")

    words = mnemonic_from_dice(rolls)
    print(' '.join(words))



if __name__ == "__main__":
    main()
