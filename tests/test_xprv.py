import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.test_bip85 import BIP39_ENGLISH_VECTORS


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
XPRV = load_module("xprv", ROOT / "xprv.py")

# Public vectors used below (retrieved 2026-08-27):
#
# - All 24 canonical English BIP39 vectors:
#   https://github.com/trezor/python-mnemonic/blob/master/vectors.json
# - The BIP86 end-to-end mnemonic/root-xprv vector (empty passphrase):
#   https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
# - Extra 15- and 21-word vectors, which the canonical set omits, plus two
#   empty-passphrase seed vectors:
#   https://github.com/osem23/bip39-wordlists-tzur/blob/main/test-vectors/english.json
# - Invalid mnemonic cases:
#   https://github.com/ebellocchia/bip_utils/blob/master/tests/bip/bip39/test_bip39.py

BIP86_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about"
)
BIP86_ROOT_XPRV = (
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisri"
    "DvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
)

MIDDLE_WORD_COUNT_VECTORS = [
    (
        "legal winner thank year wave sausage worth useful legal winner thank "
        "year wave sausage wise",
        "TREZOR",
        "f938c2f3ebd11f1c9057b713d977b5260e4282a57811ab163a9708c4ce153079"
        "83ac24c4451c7cb353b2002d0a1ee8a404fa59f0f6aa8323fa9bb61248cf4808",
    ),
    (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
        "zoo zoo zoo veteran",
        "TREZOR",
        "4aa0af4ca02ef1d9fa675cd02aa06d318425564e7fadd3d51b6165cc56d77398"
        "f28d8522073cd036c2a4a24a83e919211c84500d96cb120084e613ff5fcd96c1",
    ),
]

EMPTY_PASSPHRASE_SEED_VECTORS = [
    (
        BIP86_MNEMONIC,
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19"
        "a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    ),
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon art",
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
        "5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
    ),
]


class XprvTest(unittest.TestCase):
    def test_matches_bip86_end_to_end_vector(self):
        self.assertEqual(
            BIP86_ROOT_XPRV,
            XPRV.xprv_from_seed(XPRV.seed_from_mnemonic(BIP86_MNEMONIC)),
        )

    def test_mnemonic_to_seed_matches_all_public_empty_passphrase_vectors(self):
        for mnemonic, seed_hex in EMPTY_PASSPHRASE_SEED_VECTORS:
            with self.subTest(words=len(mnemonic.split())):
                self.assertEqual(bytes.fromhex(seed_hex), XPRV.seed_from_mnemonic(mnemonic))

    def test_seed_and_root_xprv_match_all_canonical_english_vectors(self):
        # The canonical vectors use passphrase "TREZOR". Testing the two stages
        # separately leaves the CLI's documented empty passphrase unchanged
        # while still checking every published seed and root xprv.
        self.assertEqual(24, len(BIP39_ENGLISH_VECTORS))
        for entropy_hex, mnemonic, seed_hex, root_xprv in BIP39_ENGLISH_VECTORS:
            with self.subTest(entropy=entropy_hex, words=len(mnemonic.split())):
                seed = XPRV.seed_from_mnemonic(mnemonic, "TREZOR")
                self.assertEqual(bytes.fromhex(seed_hex), seed)
                self.assertEqual(root_xprv, XPRV.xprv_from_seed(seed))

    def test_public_vectors_cover_every_allowed_word_count(self):
        vectors = [
            (mnemonic, "TREZOR", seed_hex)
            for _entropy, mnemonic, seed_hex, _xprv in BIP39_ENGLISH_VECTORS
        ]
        vectors.extend(MIDDLE_WORD_COUNT_VECTORS)

        observed_word_counts = set()
        for mnemonic, passphrase, seed_hex in vectors:
            word_count = len(mnemonic.split())
            observed_word_counts.add(word_count)
            with self.subTest(words=word_count, mnemonic=mnemonic):
                self.assertEqual(
                    bytes.fromhex(seed_hex),
                    XPRV.seed_from_mnemonic(mnemonic, passphrase),
                )

        self.assertEqual(set(XPRV.WORD_COUNTS), observed_word_counts)

    def test_normalizes_case_and_whitespace(self):
        decorated = "\n  " + "\t".join(BIP86_MNEMONIC.upper().split()) + "  \n"
        self.assertEqual(
            BIP86_ROOT_XPRV,
            XPRV.xprv_from_seed(XPRV.seed_from_mnemonic(decorated)),
        )

    def test_rejects_public_invalid_mnemonic_vectors(self):
        invalid_vectors = [
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon",
                "mnemonic must have 12, 15, 18, 21, or 24 words",
            ),
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon any",
                "invalid BIP39 checksum",
            ),
            (
                "abandon abandon abandon notexistent abandon abandon abandon "
                "abandon abandon abandon abandon about",
                "unknown BIP39 word: notexistent",
            ),
        ]

        for mnemonic, message in invalid_vectors:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, f"^{message}$"):
                    XPRV.seed_from_mnemonic(mnemonic)

    def test_rejects_invalid_bip32_root_private_keys(self):
        for private_key in (0, XPRV.SECP256K1_N):
            digest = private_key.to_bytes(32, "big") + b"\x01" * 32
            fake_hmac = mock.Mock()
            fake_hmac.digest.return_value = digest

            with self.subTest(private_key=private_key):
                with mock.patch.object(XPRV.hmac, "new", return_value=fake_hmac):
                    with self.assertRaisesRegex(ValueError, "^invalid BIP32 root key$"):
                        XPRV.xprv_from_seed(b"public test seed")

    def test_cli_prints_bip86_root_xprv(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "xprv.py")],
            input=BIP86_MNEMONIC + "\n",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode)
        self.assertEqual(
            f"Derive root xprv from mnemonic: {BIP86_ROOT_XPRV}\n",
            result.stdout,
        )
        self.assertEqual("", result.stderr)

    def test_cli_reports_invalid_mnemonic(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "xprv.py")],
            input="abandon\n",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("Derive root xprv from mnemonic: ", result.stdout)
        self.assertEqual(
            "mnemonic must have 12, 15, 18, 21, or 24 words\n",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
