#!/usr/bin/env python3
"""Example: Format-preserving encryption of IP addresses.

Encrypts IP addresses while preserving:
- IPv4 format (XXX.XXX.XXX.XXX)
- IPv6 format (XXXX:XXXX:...)
- Dot/colon separators
"""

import ffx


def encrypt_ipv4(ip: str, ffx_obj) -> str:
    """Encrypt an IPv4 address, preserving format.
    
    Each octet is encrypted separately to maintain valid-looking output.
    Note: Encrypted octets may exceed 255.
    
    Args:
        ip: IPv4 address (e.g., "192.168.1.1")
        ffx_obj: FFX encrypter configured with radix=10
    
    Returns:
        Encrypted IPv4-like address
    """
    octets = ip.split('.')
    if len(octets) != 4:
        raise ValueError("Invalid IPv4 address")
    
    encrypted_octets = []
    for octet in octets:
        # Pad to 3 digits for consistent encryption
        padded = octet.zfill(3)
        plain = ffx.FFXInteger(padded, radix=10, blocksize=3)
        encrypted = ffx_obj.encrypt(0, plain)
        # Keep as 3 digits, strip leading zeros for display
        encrypted_octets.append(str(int(str(encrypted).zfill(3))))
    
    return '.'.join(encrypted_octets)


def decrypt_ipv4(encrypted_ip: str, ffx_obj) -> str:
    """Decrypt an IPv4 address."""
    octets = encrypted_ip.split('.')
    
    decrypted_octets = []
    for octet in octets:
        padded = octet.zfill(3)
        cipher = ffx.FFXInteger(padded, radix=10, blocksize=3)
        decrypted = ffx_obj.decrypt(0, cipher)
        decrypted_octets.append(str(int(str(decrypted).zfill(3))))
    
    return '.'.join(decrypted_octets)


def encrypt_ipv6(ip: str, ffx_obj) -> str:
    """Encrypt an IPv6 address, preserving format.
    
    Args:
        ip: IPv6 address (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        ffx_obj: FFX encrypter configured with radix=16
    
    Returns:
        Encrypted IPv6 address
    """
    # Handle :: shorthand by expanding
    if '::' in ip:
        parts = ip.split('::')
        left = parts[0].split(':') if parts[0] else []
        right = parts[1].split(':') if parts[1] else []
        missing = 8 - len(left) - len(right)
        groups = left + ['0000'] * missing + right
    else:
        groups = ip.split(':')
    
    # Normalize to 4-digit groups
    groups = [g.zfill(4) for g in groups]
    
    encrypted_groups = []
    for group in groups:
        plain = ffx.FFXInteger(group.lower(), radix=16, blocksize=4)
        encrypted = ffx_obj.encrypt(0, plain)
        encrypted_groups.append(str(encrypted).zfill(4))
    
    return ':'.join(encrypted_groups)


def decrypt_ipv6(encrypted_ip: str, ffx_obj) -> str:
    """Decrypt an IPv6 address."""
    groups = encrypted_ip.split(':')
    
    decrypted_groups = []
    for group in groups:
        cipher = ffx.FFXInteger(group.lower(), radix=16, blocksize=4)
        decrypted = ffx_obj.decrypt(0, cipher)
        decrypted_groups.append(str(decrypted).zfill(4))
    
    return ':'.join(decrypted_groups)


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_decimal = ffx.new(key.to_bytes(16), radix=10)
    ffx_hex = ffx.new(key.to_bytes(16), radix=16)
    
    print("IP Address Format-Preserving Encryption")
    print("=" * 60)
    
    # IPv4 addresses
    ipv4_addrs = ["192.168.1.1", "10.0.0.1", "172.16.254.1", "8.8.8.8"]
    print("\n--- IPv4 Addresses ---")
    for ip in ipv4_addrs:
        encrypted = encrypt_ipv4(ip, ffx_decimal)
        decrypted = decrypt_ipv4(encrypted, ffx_decimal)
        print(f"Original: {ip:15} → Encrypted: {encrypted:15} → Verified: {'✓' if ip == decrypted else '✗'}")
    
    # IPv6 addresses
    ipv6_addrs = [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80:0000:0000:0000:0000:0000:0000:0001",
    ]
    print("\n--- IPv6 Addresses ---")
    for ip in ipv6_addrs:
        encrypted = encrypt_ipv6(ip, ffx_hex)
        decrypted = decrypt_ipv6(encrypted, ffx_hex)
        print(f"Original:  {ip}")
        print(f"Encrypted: {encrypted}")
        print(f"Verified:  {'✓' if ip.lower() == decrypted.lower() else '✗'}")
        print()


if __name__ == "__main__":
    main()
