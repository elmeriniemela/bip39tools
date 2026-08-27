import importlib.util
import random
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT

DICE_FACES = "123456"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DICE = load_module("dice", SRC / "dice.py")


def random_rolls(count):
    return "".join(random.choice(DICE_FACES) for _ in range(count))


def bc_sed_words(word_count, rolls):
    entropy_hex_digits, checksum_hex_digits = {12: (32, 1), 24: (64, 2)}[word_count]

    return subprocess.check_output(
        [
            "bash",
            "-c",
            """
set -euo pipefail
h=$(printf %s "$1" | sha256sum | cut -c "1-$2")
h+=$(xxd -r -p <<<"$h" | sha256sum | cut -c "1-$3")
BC_LINE_LENGTH=0 bc <<<"obase=2048;ibase=16;1${h^^}" |
  xargs -n1 |
  sed -e '1d' -f bip39-bc2048.sed |
  paste -sd' '
""",
            "bc_sed_words",
            rolls,
            str(entropy_hex_digits),
            str(checksum_hex_digits),
        ],
        cwd=ROOT,
        text=True,
    ).split()


class DiceWordMappingFuzzTest(unittest.TestCase):
    def test_documented_methods_produce_the_same_words_for_random_rolls(self):
        for word_count, roll_count in ((12, 50), (24, 99)):
            for case in range(32):
                rolls = random_rolls(roll_count)

                with self.subTest(words=word_count, case=case, rolls=rolls):
                    dice_words = DICE.mnemonic_from_dice(rolls)
                    bash_words = bc_sed_words(word_count, rolls)

                    self.assertEqual(word_count, len(dice_words))
                    self.assertEqual(dice_words, bash_words)


if __name__ == "__main__":
    unittest.main()
