#!/usr/bin/env python3
"""Example: Format-preserving encryption of email addresses.

This example demonstrates how to encrypt email addresses while preserving
their format. The encrypted output remains a valid-looking email address.

FFX uses a radix-based alphabet (2-36), so we encrypt alphanumeric parts
separately while preserving special characters like @ and dots.
"""

import re

import ffx


def encrypt_email(email: str, ffx_obj) -> str:
    """Encrypt an email address while preserving its format.
    
    Encrypts alphanumeric parts using radix-36 FFX, preserves structure
    characters (@, dots, hyphens, etc).
    
    Args:
        email: Email address to encrypt (will be lowercased)
        ffx_obj: FFX encrypter configured with radix=36
    
    Returns:
        Encrypted email address with same structure
    
    Example:
        >>> key = ffx.FFXInteger('0' * 32, radix=16, blocksize=32)
        >>> ffx_obj = ffx.new(key.to_bytes(16), radix=36)
        >>> encrypt_email("john.doe@example.com", ffx_obj)
        'j9ky.5rf@q2z0h5i.nfd'
    """
    local, domain = email.lower().split('@')
    
    def encrypt_part(part: str) -> str:
        # Split on non-alphanumeric, keeping separators
        segments = re.split(r'([^a-z0-9]+)', part)
        result = []
        for seg in segments:
            if seg and re.match(r'^[a-z0-9]+$', seg):
                # Encrypt alphanumeric segments
                plain = ffx.FFXInteger(seg, radix=36, blocksize=len(seg))
                encrypted = ffx_obj.encrypt(0, plain)
                result.append(str(encrypted))
            else:
                # Keep separators (dots, hyphens, etc) as-is
                result.append(seg)
        return ''.join(result)
    
    encrypted_local = encrypt_part(local)
    encrypted_domain = encrypt_part(domain)
    
    return f"{encrypted_local}@{encrypted_domain}"


def decrypt_email(encrypted_email: str, ffx_obj) -> str:
    """Decrypt an email address.
    
    Args:
        encrypted_email: Previously encrypted email address
        ffx_obj: FFX encrypter configured with radix=36 (same key as encryption)
    
    Returns:
        Original email address
    """
    local, domain = encrypted_email.split('@')
    
    def decrypt_part(part: str) -> str:
        segments = re.split(r'([^a-z0-9]+)', part)
        result = []
        for seg in segments:
            if seg and re.match(r'^[a-z0-9]+$', seg):
                cipher = ffx.FFXInteger(seg, radix=36, blocksize=len(seg))
                decrypted = ffx_obj.decrypt(0, cipher)
                result.append(str(decrypted))
            else:
                result.append(seg)
        return ''.join(result)
    
    return f"{decrypt_part(local)}@{decrypt_part(domain)}"


def main():
    # Create a 128-bit key (use a secure random key in production!)
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    
    # Create FFX encrypter with radix=36 (alphanumeric: 0-9, a-z)
    ffx_obj = ffx.new(key.to_bytes(16), radix=36)
    
    # Example email addresses
    emails = [
        "john.doe@example.com",
        "alice+newsletter@company.org",
        "user123@mail-server.co.uk",
        "contact@subdomain.example.com",
    ]
    
    print("Email Address Format-Preserving Encryption Demo")
    print("=" * 60)
    
    for email in emails:
        encrypted = encrypt_email(email, ffx_obj)
        decrypted = decrypt_email(encrypted, ffx_obj)
        
        print(f"\nOriginal:  {email}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'✓' if decrypted == email.lower() else '✗'}")


if __name__ == "__main__":
    main()
