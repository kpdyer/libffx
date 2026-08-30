#!/usr/bin/env python3
"""Example: Format-preserving encryption of bank account numbers.

Encrypts bank account and routing numbers while preserving:
- Numeric format and length
- Common formatting (spaces, dashes)

Routing and account numbers are encrypted with distinct tweaks so equal
digit strings in the two roles produce unrelated ciphertexts.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(number: str, cipher: FF1, tweak: bytes, *, encrypt: bool) -> str:
    digits = "".join(c for c in number if c.isdigit())
    if len(digits) < 6:
        raise ValueError(f"need at least 6 digits, got {len(digits)}")
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_digits = iter(op(digits, tweak=tweak))
    return "".join(next(new_digits) if c.isdigit() else c for c in number)


def encrypt_routing_number(routing: str, cipher: FF1) -> str:
    """Encrypt a 9-digit ABA routing number. `cipher` must use radix=10."""
    return _transform(routing, cipher, b"routing", encrypt=True)


def decrypt_routing_number(routing: str, cipher: FF1) -> str:
    return _transform(routing, cipher, b"routing", encrypt=False)


def encrypt_account_number(account: str, cipher: FF1) -> str:
    """Encrypt a bank account number (6+ digits). `cipher` must use radix=10."""
    return _transform(account, cipher, b"account", encrypt=True)


def decrypt_account_number(account: str, cipher: FF1) -> str:
    return _transform(account, cipher, b"account", encrypt=False)


def main():
    cipher = FF1(KEY, radix=10)

    accounts = [
        ("021000021", "1234567890"),
        ("111000025", "9876-543-210"),
        ("026009593", "555 0123 456789"),
    ]

    print("Bank Account Format-Preserving Encryption")
    print("=" * 50)

    for routing, account in accounts:
        enc_routing = encrypt_routing_number(routing, cipher)
        enc_account = encrypt_account_number(account, cipher)
        dec_routing = decrypt_routing_number(enc_routing, cipher)
        dec_account = decrypt_account_number(enc_account, cipher)

        ok = dec_routing == routing and dec_account == account
        print(f"\nOriginal:  routing {routing}  account {account}")
        print(f"Encrypted: routing {enc_routing}  account {enc_account}")
        print(f"Decrypted: routing {dec_routing}  account {dec_account}")
        print(f"Verified:  {'ok' if ok else 'MISMATCH'}")


if __name__ == "__main__":
    main()
