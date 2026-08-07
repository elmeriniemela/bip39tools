
## BIP-39 Tools

Misc BIP39 related tools/scripts.

Run the automated tests from this directory with:

```sh
python3 -m unittest discover -s tests
```


### 1. Dice rolls BIP39(SHA256(rolls_ascii))
Technical specification for transforming dice rolls into seed words:

1. The input is the dice-roll string as ASCII digits `1` through `6`. Whitespace is ignored by the helper scripts.
2. For a 12-word use 50 rolls. For a 24-word seed, use 99 rolls.
3. Compute `digest = SHA256(rolls_ascii)` (not part of BIP39, but removes possiblle statistical bias from rolls).
4. Select the BIP39 entropy bytes from `digest`:
   * 12 words: `entropy = digest[0:16]`, 128 bits.
   * 24 words: `entropy = digest[0:32]`, 256 bits.
5. Compute the BIP39 checksum from the selected entropy bytes, by taking the first len(entropy) // 32 bits of its SHA256:
   * `checksum = SHA256(entropy)`.
   * 12 words: append the first 4 checksum bits.
   * 24 words: append the first 8 checksum bits.
6. Write `entropy || checksum_bits` as a big-endian bit string: most significant bit first for each byte.
7. Split that bit string into 11-bit groups. A 12-word seed has 132 bits and therefore 12 groups; a 24-word seed has 264 bits and therefore 24 groups.
8. Interpret each 11-bit group as an unsigned integer `0..2047`.
9. Use that integer as a zero-based index into `bip39-eng.txt`; equivalently, word index `n` is line `n + 1`.
10. Join the selected words with spaces.

```sh
# Generate 50 random dice faces for a 12-word seed test. Dependencies: tr, head.
tr -dc '1-6' </dev/urandom | head -c 50; echo
# Verify the 12-word SeedSigner result for the sample dice rolls. Dependencies: python3+std libraries: hashlib.sha256, argparse, pathlib
rolls=44266664153554464254321232633466466235664323326523; ./ss-dice.py -n 12 "$rolls"
# Verify the 12-word COLDCARD result for the sample dice rolls. Dependencies: python3+std libraries: hashlib.sha256, argparse, pathlib
rolls=44266664153554464254321232633466466235664323326523; ./cc-dice.py -n 12 "$rolls"
# Convert the sample rolls to BIP39 words by using bc base-2048 output and a
# checked-in sed map from base-2048 digits to BIP39 words. Dependencies: bash,
# sha256sum, cut, xxd, bc, xargs, sed, paste
#
# Trace for the sample rolls:
# - rolls=... sets the input dice digits for this 50-roll, 12-word example
#   (Spec 1, Spec 2):
#   44266664153554464254321232633466466235664323326523
# - printf %s "$rolls" sends those exact ASCII bytes into sha256sum, without
#   adding a newline (Spec 1, Spec 3).
# - sha256sum sends this dice-roll digest line into cut (Spec 3):
#   f089b58c8ff66a5c6cc2a996c235969d526ba4ed59037f8f892346e4c3883bfb  -
# - cut -c1-32 keeps the first 16 entropy bytes for a 12-word seed, so h
#   becomes (Spec 4):
#   f089b58c8ff66a5c6cc2a996c235969d
# - xxd -r -p <<<"$h" converts h from hex to raw entropy bytes and sends those
#   bytes into sha256sum for the BIP39 checksum (Spec 5). Shown as hex:
#   f0 89 b5 8c 8f f6 6a 5c 6c c2 a9 96 c2 35 96 9d
# - sha256sum sends this entropy-checksum digest line into cut (Spec 5):
#   e630926e1e130db1dd3c5704b344bfd9de34c168fa50332ed92d6def9da1897f  -
# - cut -c1 keeps the first checksum nibble, e, and h+=... appends those
#   4 checksum bits to the entropy for a 12-word seed. h is now
#   entropy || checksum_bits (Spec 5, Spec 6):
#   f089b58c8ff66a5c6cc2a996c235969de
# - BC_LINE_LENGTH=0 prevents bc from wrapping the base-2048 output before it
#   is piped to xargs.
# - bc receives this expression. The leading 1 is a sentinel so leading zero
#   base-2048 groups are preserved; ${h^^} uppercases h for ibase=16. This
#   treats h as the big-endian bit string from Spec 6:
#   obase=2048;ibase=16;1F089B58C8FF66A5C6CC2A996C235969DE
# - bc sends these base-2048 groups into xargs. Ignoring the sentinel, these
#   are the 11-bit groups interpreted as integers (Spec 7, Spec 8):
#   0001 1924 0621 0793 0255 0821 0369 1432 0681 1206 0141 0813 0478
# - xargs -n1 sends one group per line into sed:
#   0001
#   1924
#   0621
#   0793
#   0255
#   0821
#   0369
#   1432
#   0681
#   1206
#   0141
#   0813
#   0478
# - sed -e '1d' removes the sentinel line, then bip39-bc2048.sed maps the
#   remaining base-2048 groups to BIP39 words and sends them into paste
#   (Spec 9):
#   vacuum
#   ethics
#   glimpse
#   cable
#   grit
#   comfort
#   reason
#   festival
#   nothing
#   balance
#   grant
#   design
# - paste -sd' ' joins the words into the final one-line seed phrase (Spec 10):
#   vacuum ethics glimpse cable grit comfort reason festival nothing balance grant design
rolls=44266664153554464254321232633466466235664323326523; h=$(printf %s "$rolls"|sha256sum|cut -c1-32); h+=$(xxd -r -p<<<"$h"|sha256sum|cut -c1); BC_LINE_LENGTH=0 bc<<<"obase=2048;ibase=16;1${h^^}"|xargs -n1|sed -e '1d' -f bip39-bc2048.sed|paste -sd' '
# vacuum ethics glimpse cable grit comfort reason festival nothing balance grant design
# Regenerate the map of 11-bit integers 0..2047 into words if bip39-eng.txt ever changes.
awk '{printf "s/^%04d$/%s/\n", NR-1, $0}' bip39-eng.txt > bip39-bc2048.sed
```

Compare these three methods to each other with:
```sh
python3 -m unittest tests/test_dice_word_mapping_fuzz.py
```



### 2. Encrypt/Decrypt backup archive.

`encrypt_backup.py` creates a minimal encrypted 7z archive containing one
plaintext file named `backup.txt`. The file contains a generated comment with
a fresh random secret, followed by the mnemonic line:

```text
# Generated by bip39tools/encrypt_backup.py. Nonce: <64 hex characters>
mnemonic = "word word ... word"
```

The scripts use only Python standard libraries and `bip39-eng.txt`.

```sh
# Create an encrypted backup archive. The mnemonic must be 12 or 24 BIP39 words.
python3 encrypt_backup.py backup.7z
# Prompts for the mnemonic, archive passphrase, and passphrase confirmation
# with hidden terminal input.

# Decrypt the archive and print backup.txt to stdout.
python3 decrypt_backup.py backup.7z
# Prompts for the archive passphrase with hidden terminal input.
# # Generated by bip39tools/encrypt_backup.py. Nonce: ...
# mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

The archive password is the encryption password for the 7z file. It is not a
BIP39 passphrase, and no BIP39-passphrase wallet derivation is performed.

#### Encrypted archive generation specification

1. Normalize and validate the input mnemonic:
   * split the provided words on whitespace,
   * lowercase each word,
   * require exactly 12 or 24 words,
   * require every word to be present in `bip39-eng.txt`.
2. Build the plaintext as UTF-8 bytes:

   ```text
   # Generated by bip39tools/encrypt_backup.py. Nonce: <64 hex characters>
   mnemonic = "word word ... word"
   ```

   The nonce is 32 random bytes encoded with `secrets.token_hex(32)`. The
   plaintext ends with one newline byte (`0x0a`).
3. Generate independent 16-byte salts and 16-byte IVs with
   `secrets.token_bytes` for the file data stream and encoded header stream.
4. Derive each AES-256 key with the 7z AES/SHA-256 KDF:

   ```python
   password_bytes = password.encode("utf-16-le")
   digest = hashlib.sha256()
   for i in range(16_777_216):  # 1 << ROUNDS_POWER, where ROUNDS_POWER = 24
       digest.update(salt)
       digest.update(password_bytes)
       digest.update(struct.pack("<Q", i))
   key = digest.digest()
   ```

5. Pad the plaintext with zero bytes to at least 1024 bytes, then to a
   16-byte boundary. The original plaintext length is stored only in the
   encrypted header, so standard extractors remove both AES block padding and
   cover padding during decryption.
6. Encrypt the padded plaintext with AES-256-CBC using the derived key and IV.
   No compression is used.
7. Build the normal single-file 7z header containing the file-data AES/SHA-256
   coder (`06 f1 07 01`), file-data KDF properties, original plaintext size,
   plaintext CRC32, and one UTF-16-LE filename entry for `backup.txt`.
8. Pad and encrypt that normal header as a second AES-256-CBC stream.
9. Write a minimal single-file 7z container with standard encoded-header
   metadata:
   * file signature: `37 7a bc af 27 1c`,
   * version: major `0`, minor `4`,
   * next-header CRC32: CRC32 of the 20-byte section header,
   * section header: little-endian `uint64` offset to the final next header,
     little-endian `uint64` final next-header length, CRC32 of the final
     next header,
   * encrypted body: AES-256-CBC ciphertext from step 6,
   * encrypted encoded-header body: AES-256-CBC ciphertext from step 8,
   * final next header: `kEncodedHeader` (`0x17`) describing how to decrypt the
     encrypted encoded-header body.

The generated archives use standard 7z header encryption, so standard archivers
can open them with the archive passphrase. Without the passphrase, the exact
plaintext size, plaintext CRC32, and `backup.txt` filename are not present in
the clear header. The outer 7z structure still reveals archive size and the
fixed 1024-byte encrypted file-data bucket used for these small backups.

All variable-width 7z integers generated by the script use its `encode_var64`
encoding.

```sh
python3 -m unittest tests/test_backup_archive.py
```
