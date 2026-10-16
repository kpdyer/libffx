#!/usr/bin/env python3
"""Encrypt entire IP addresses as integers, preserving the address family.

Run with: python -m examples.ip_address
"""

import ipaddress
import secrets

from ffx import FF1


def transform(ip: str, cipher: FF1, *, decrypt: bool = False) -> str:
    """Encrypt (or decrypt) an IPv4 or IPv6 address to another address of
    the same family."""
    addr = ipaddress.ip_address(ip)
    operation = cipher.decrypt_int if decrypt else cipher.encrypt_int
    value = operation(int(addr), domain=2 ** addr.max_prefixlen, tweak=b"ip")
    # Rebuild with the same class: ip_address() would turn a small IPv6
    # value into an IPv4 address.
    return str(type(addr)(value))


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
    for ip in ips:
        encrypted = transform(ip, cipher)
        decrypted = transform(encrypted, cipher, decrypt=True)
        assert decrypted == str(ipaddress.ip_address(ip))
        print(f"{ip} -> {encrypted} -> {decrypted}")


if __name__ == "__main__":
    main()
