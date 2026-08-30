#!/usr/bin/env python3
"""Example: Format-preserving encryption of medical record numbers (MRN).

Encrypts MRNs while preserving:
- Alphanumeric format and length
- Separator positions
- An optional letter prefix such as a facility code (e.g. "MRN-", "AB-"),
  kept in the clear when it is set off by a separator

The rest is encrypted as one radix-36 block, with the preserved prefix
bound into the tweak so the same digits encrypt differently under
different prefixes. The prefix split keys off the separator, which
survives encryption in place, so it is unambiguous in both directions.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _split_prefix(mrn: str, preserve_prefix: bool) -> tuple[str, str]:
    """Split "abc-123..." into ("abc-", "123..."), else ("", mrn)."""
    if preserve_prefix:
        i = 0
        while i < len(mrn) and mrn[i].isalpha():
            i += 1
        # A prefix only counts if a separator follows it; the separator is
        # preserved by encryption, so decryption splits identically.
        if 1 <= i <= 4 and i < len(mrn) and not mrn[i].isalnum():
            return mrn[: i + 1], mrn[i + 1:]
    return "", mrn


def _transform(body: str, prefix: str, cipher: FF1, *, encrypt: bool) -> str:
    chars = "".join(c for c in body if c.isalnum())
    op = cipher.encrypt if encrypt else cipher.decrypt
    tweak = b"mrn:" + prefix.encode("ascii")
    new_chars = iter(op(chars, tweak=tweak))
    return "".join(next(new_chars) if c.isalnum() else c for c in body)


def encrypt_mrn(mrn: str, cipher: FF1, preserve_prefix: bool = False) -> str:
    """Encrypt an MRN (lowercased). `cipher` must use radix=36."""
    prefix, body = _split_prefix(mrn.lower(), preserve_prefix)
    return prefix + _transform(body, prefix, cipher, encrypt=True)


def decrypt_mrn(encrypted_mrn: str, cipher: FF1, preserve_prefix: bool = False) -> str:
    """Decrypt an MRN."""
    prefix, body = _split_prefix(encrypted_mrn, preserve_prefix)
    return prefix + _transform(body, prefix, cipher, encrypt=False)


def main():
    cipher = FF1(KEY, radix=36, allow_small_domain=True)

    mrns = [
        "MRN-12345678",
        "AB-9876543",
        "XYZ1234567",  # no separator: prefix cannot be preserved
        "000111222",
    ]

    print("Medical Record Number Format-Preserving Encryption")
    print("=" * 50)

    for mrn in mrns:
        for preserve in (False, True):
            encrypted = encrypt_mrn(mrn, cipher, preserve_prefix=preserve)
            decrypted = decrypt_mrn(encrypted, cipher, preserve_prefix=preserve)
            label = "prefix kept" if preserve else "all encrypted"

            print(f"\nOriginal:  {mrn}  ({label})")
            print(f"Encrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")
            print(f"Verified:  {'ok' if mrn.lower() == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
