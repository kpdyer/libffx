#!/usr/bin/env python3
"""Encrypt entire IP addresses as integers, preserving the address family.

Run with: python -m examples.ip_address
"""

import ipaddress
import secrets

from ffx import FF1


def encrypt_ip(ip: str, cipher: FF1) -> str:
    """Encrypt an IPv4 or IPv6 address to another valid address."""
    addr = ipaddress.ip_address(ip)
    domain = 2 ** (32 if addr.version == 4 else 128)
    encrypted = cipher.encrypt_int(int(addr), domain=domain, tweak=b"ip")
    return str(type(addr)(encrypted))


def decrypt_ip(ip: str, cipher: FF1) -> str:
    """Decrypt an address produced by encrypt_ip."""
    addr = ipaddress.ip_address(ip)
    domain = 2 ** (32 if addr.version == 4 else 128)
    decrypted = cipher.decrypt_int(int(addr), domain=domain, tweak=b"ip")
    return str(type(addr)(decrypted))


def main():
    cipher = FF1(secrets.token_bytes(16))

    ips = [
        "192.168.1.1",
        "10.0.0.42",
        "8.8.8.8",
        "2001:db8::8a2e:370:7334",
        "fe80::1",
        "::",
        "::1",
    ]

    print("IP Address Format-Preserving Encryption")
    print("=" * 50)

    for ip in ips:
        encrypted = encrypt_ip(ip, cipher)
        decrypted = decrypt_ip(encrypted, cipher)
        assert decrypted == str(ipaddress.ip_address(ip))

        print(f"\nOriginal:  {ip}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()
