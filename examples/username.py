#!/usr/bin/env python3
"""Example: Format-preserving encryption of usernames.

Encrypts usernames while preserving:
- Alphanumeric characters
- Allowed special characters (underscore, dot, dash)
- Length and format
"""

import re

import ffx


def encrypt_username(username: str, ffx_obj) -> str:
    """Encrypt a username, preserving format.
    
    Encrypts alphanumeric segments, preserves underscores, dots, dashes.
    
    Args:
        username: Username string (lowercase alphanumeric + _.-) 
        ffx_obj: FFX encrypter configured with radix=36
    
    Returns:
        Encrypted username with same format
    """
    # Split into alphanumeric segments and separators
    parts = re.split(r'([^a-z0-9]+)', username.lower())
    
    result = []
    for part in parts:
        if part and part[0].isalnum():
            plain = ffx.FFXInteger(part, radix=36, blocksize=len(part))
            encrypted = ffx_obj.encrypt(0, plain)
            result.append(str(encrypted).zfill(len(part)))
        else:
            # Keep separators (_, ., -)
            result.append(part)
    
    return ''.join(result)


def decrypt_username(encrypted_username: str, ffx_obj) -> str:
    """Decrypt a username."""
    parts = re.split(r'([^a-z0-9]+)', encrypted_username.lower())
    
    result = []
    for part in parts:
        if part and part[0].isalnum():
            cipher = ffx.FFXInteger(part, radix=36, blocksize=len(part))
            decrypted = ffx_obj.decrypt(0, cipher)
            result.append(str(decrypted).zfill(len(part)))
        else:
            result.append(part)
    
    return ''.join(result)


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_obj = ffx.new(key.to_bytes(16), radix=36)
    
    print("Username Format-Preserving Encryption")
    print("=" * 50)
    
    usernames = [
        "john_doe",
        "alice.smith",
        "bob-jones123",
        "user2024",
        "admin_test.account",
        "x",
        "anonymous",
    ]
    
    for username in usernames:
        encrypted = encrypt_username(username, ffx_obj)
        decrypted = decrypt_username(encrypted, ffx_obj)
        
        print(f"\nOriginal:  {username}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'✓' if username.lower() == decrypted else '✗'}")


if __name__ == "__main__":
    main()
