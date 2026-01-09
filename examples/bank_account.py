#!/usr/bin/env python3
"""Example: Format-preserving encryption of bank account numbers.

Encrypts bank account and routing numbers while preserving:
- Numeric format
- Length
- Common formatting (spaces, dashes)
"""

import ffx


def encrypt_account_number(account: str, ffx_obj) -> str:
    """Encrypt a bank account number.
    
    Args:
        account: Account number (digits only or with formatting)
        ffx_obj: FFX encrypter configured with radix=10
    
    Returns:
        Encrypted account number with same length
    """
    digits = ''.join(c for c in account if c.isdigit())
    
    if len(digits) < 4:
        raise ValueError("Account number too short")
    
    plain = ffx.FFXInteger(digits, radix=10, blocksize=len(digits))
    encrypted = ffx_obj.encrypt(0, plain)
    
    return str(encrypted).zfill(len(digits))


def decrypt_account_number(encrypted: str, ffx_obj) -> str:
    """Decrypt a bank account number."""
    cipher = ffx.FFXInteger(encrypted, radix=10, blocksize=len(encrypted))
    decrypted = ffx_obj.decrypt(0, cipher)
    return str(decrypted).zfill(len(encrypted))


def encrypt_routing_number(routing: str, ffx_obj) -> str:
    """Encrypt a 9-digit ABA routing number."""
    digits = ''.join(c for c in routing if c.isdigit())
    
    if len(digits) != 9:
        raise ValueError("Routing number must be 9 digits")
    
    plain = ffx.FFXInteger(digits, radix=10, blocksize=9)
    encrypted = ffx_obj.encrypt(0, plain)
    
    return str(encrypted).zfill(9)


def decrypt_routing_number(encrypted: str, ffx_obj) -> str:
    """Decrypt a routing number."""
    cipher = ffx.FFXInteger(encrypted, radix=10, blocksize=9)
    decrypted = ffx_obj.decrypt(0, cipher)
    return str(decrypted).zfill(9)


def encrypt_iban(iban: str, ffx_obj_alpha, ffx_obj_num) -> str:
    """Encrypt an IBAN (International Bank Account Number).
    
    Preserves the country code (first 2 letters) and encrypts the rest.
    """
    clean = iban.upper().replace(' ', '')
    country = clean[:2]  # Preserve country code
    rest = clean[2:]
    
    # Separate letters and digits
    result = country
    for char in rest:
        if char.isdigit():
            plain = ffx.FFXInteger(char, radix=10, blocksize=1)
            enc = ffx_obj_num.encrypt(0, plain)
            result += str(enc)
        elif char.isalpha():
            plain = ffx.FFXInteger(char.lower(), radix=36, blocksize=1)
            enc = ffx_obj_alpha.encrypt(0, plain)
            result += str(enc).upper()
    
    # Format with spaces every 4 characters
    return ' '.join(result[i:i+4] for i in range(0, len(result), 4))


def decrypt_iban(encrypted: str, ffx_obj_alpha, ffx_obj_num) -> str:
    """Decrypt an IBAN."""
    clean = encrypted.upper().replace(' ', '')
    country = clean[:2]
    rest = clean[2:]
    
    result = country
    for char in rest:
        if char.isdigit():
            cipher = ffx.FFXInteger(char, radix=10, blocksize=1)
            dec = ffx_obj_num.decrypt(0, cipher)
            result += str(dec)
        elif char.isalpha():
            cipher = ffx.FFXInteger(char.lower(), radix=36, blocksize=1)
            dec = ffx_obj_alpha.decrypt(0, cipher)
            result += str(dec).upper()
    
    return ' '.join(result[i:i+4] for i in range(0, len(result), 4))


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_num = ffx.new(key.to_bytes(16), radix=10)
    ffx_alpha = ffx.new(key.to_bytes(16), radix=36)
    
    print("Bank Account Format-Preserving Encryption")
    print("=" * 60)
    
    # Account numbers
    accounts = ["1234567890", "9876543210123", "00001111222233"]
    print("\n--- Account Numbers ---")
    for acct in accounts:
        encrypted = encrypt_account_number(acct, ffx_num)
        decrypted = decrypt_account_number(encrypted, ffx_num)
        print(f"Original: {acct:20} → Encrypted: {encrypted:20} → Verified: {'✓' if acct == decrypted else '✗'}")
    
    # Routing numbers
    routings = ["021000021", "121042882", "322271627"]
    print("\n--- Routing Numbers ---")
    for routing in routings:
        encrypted = encrypt_routing_number(routing, ffx_num)
        decrypted = decrypt_routing_number(encrypted, ffx_num)
        print(f"Original: {routing} → Encrypted: {encrypted} → Verified: {'✓' if routing == decrypted else '✗'}")
    
    # IBANs
    ibans = ["DE89 3704 0044 0532 0130 00", "GB82 WEST 1234 5698 7654 32"]
    print("\n--- IBANs ---")
    for iban in ibans:
        encrypted = encrypt_iban(iban, ffx_alpha, ffx_num)
        decrypted = decrypt_iban(encrypted, ffx_alpha, ffx_num)
        print(f"Original:  {iban}")
        print(f"Encrypted: {encrypted}")
        print(f"Verified:  {'✓' if iban == decrypted else '✗'}")
        print()


if __name__ == "__main__":
    main()
