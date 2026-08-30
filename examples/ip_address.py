#!/usr/bin/env python3
"""Example: Format-preserving encryption of IP addresses.

Encrypts IP addresses while preserving validity:
- IPv4 addresses map to IPv4 addresses (via encrypt_int over 2**32)
- IPv6 addresses map to IPv6 addresses (via encrypt_int over 2**128)

Unlike per-octet schemes, encrypting the address as one integer keeps every
output a real, parseable address.
"""

import ipaddress

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def encrypt_ip(ip: str, cipher: FF1) -> str:
    """Encrypt an IPv4 or IPv6 address to another valid address."""
    addr = ipaddress.ip_address(ip)
    domain = 2 ** (32 if addr.version == 4 else 128)
    encrypted = cipher.encrypt_int(int(addr), domain=domain, tweak=b"ip")
    return str(ipaddress.ip_address(encrypted))


def decrypt_ip(ip: str, cipher: FF1) -> str:
    """Decrypt an address produced by encrypt_ip."""
    addr = ipaddress.ip_address(ip)
    domain = 2 ** (32 if addr.version == 4 else 128)
    decrypted = cipher.decrypt_int(int(addr), domain=domain, tweak=b"ip")
    return str(ipaddress.ip_address(decrypted))


def main():
    cipher = FF1(KEY)  # the integer API needs no radix/alphabet

    ips = [
        "192.168.1.1",
        "10.0.0.42",
        "8.8.8.8",
        "2001:db8::8a2e:370:7334",
        "fe80::1",
    ]

    print("IP Address Format-Preserving Encryption")
    print("=" * 50)

    for ip in ips:
        encrypted = encrypt_ip(ip, cipher)
        decrypted = decrypt_ip(encrypted, cipher)

        print(f"\nOriginal:  {ip}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if str(ipaddress.ip_address(ip)) == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
