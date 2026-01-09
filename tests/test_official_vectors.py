"""Tests against official NIST FFX test vectors.

Test vectors from Voltage Security's submission to NIST:
http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt

All vectors use the same 128-bit AES key:
    2b7e151628aed2a6abf7158809cf4f3c
"""

import pytest
import ffx
from ffx import FFXInteger


# Official NIST test vectors
# Format: (radix, tweak, plaintext, expected_ciphertext, description)
OFFICIAL_VECTORS = [
    # Vector 1: Basic decimal encryption with tweak
    (
        10,                    # radix
        '9876543210',          # tweak
        '0123456789',          # plaintext
        '6124200773',          # expected ciphertext
        'radix=10, 10-digit message with tweak'
    ),
    # Vector 2: Decimal encryption without tweak
    (
        10,                    # radix
        None,                  # tweak (None = no tweak)
        '0123456789',          # plaintext
        '2433477484',          # expected ciphertext
        'radix=10, 10-digit message without tweak'
    ),
    # Vector 3: Shorter message (6 digits)
    (
        10,                    # radix
        '2718281828',          # tweak
        '314159',              # plaintext
        '535005',              # expected ciphertext
        'radix=10, 6-digit message (pi/e)'
    ),
    # Vector 4: 9-digit message with 7-digit tweak
    (
        10,                    # radix
        '7777777',             # tweak
        '999999999',           # plaintext
        '658229573',           # expected ciphertext
        'radix=10, 9-digit message'
    ),
    # Vector 5: Alphanumeric (base 36)
    (
        36,                    # radix
        'TQF9J5QDAGSCSPB1',    # tweak
        'C4XPWULBM3M863JH',    # plaintext
        'C8AQ3U846ZWH6QZP',    # expected ciphertext
        'radix=36, alphanumeric message'
    ),
]


class TestOfficialVectors:
    """Validate implementation against official NIST test vectors."""

    @pytest.fixture
    def ffx_key(self):
        """The standard key from NIST test vectors."""
        return FFXInteger(
            '2b7e151628aed2a6abf7158809cf4f3c',
            radix=16,
            blocksize=32
        )

    @pytest.mark.parametrize(
        'radix,tweak,plaintext,expected,description',
        OFFICIAL_VECTORS,
        ids=[v[4] for v in OFFICIAL_VECTORS]  # Use description as test ID
    )
    def test_encryption(self, ffx_key, radix, tweak, plaintext, expected, description):
        """Test that encryption produces expected ciphertext."""
        # Setup
        ffx_obj = ffx.new(ffx_key.to_bytes(16), radix)
        
        plain = FFXInteger(plaintext, radix=radix, blocksize=len(plaintext))
        
        if tweak is None:
            tweak_val = 0
        else:
            tweak_val = FFXInteger(tweak, radix=radix, blocksize=len(tweak))

        # Encrypt
        ciphertext = ffx_obj.encrypt(tweak_val, plain)

        # Verify (case-insensitive for alphanumeric)
        assert str(ciphertext).upper() == expected.upper()

    @pytest.mark.parametrize(
        'radix,tweak,plaintext,expected,description',
        OFFICIAL_VECTORS,
        ids=[v[4] for v in OFFICIAL_VECTORS]
    )
    def test_decryption_roundtrip(self, ffx_key, radix, tweak, plaintext, expected, description):
        """Test that decrypt(encrypt(x)) == x."""
        # Setup
        ffx_obj = ffx.new(ffx_key.to_bytes(16), radix)
        
        plain = FFXInteger(plaintext, radix=radix, blocksize=len(plaintext))
        
        if tweak is None:
            tweak_val = 0
        else:
            tweak_val = FFXInteger(tweak, radix=radix, blocksize=len(tweak))

        # Round-trip
        ciphertext = ffx_obj.encrypt(tweak_val, plain)
        decrypted = ffx_obj.decrypt(tweak_val, ciphertext)

        # Verify
        assert decrypted == plain


class TestVectorDetails:
    """Detailed tests for specific vector properties."""

    def test_tweak_affects_output(self):
        """Same plaintext with different tweaks produces different ciphertexts.
        
        Compares Vector 1 (with tweak) vs Vector 2 (no tweak).
        """
        # Setup key and encrypter
        key = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
        ffx_obj = ffx.new(key.to_bytes(16), radix=10)
        
        plaintext = FFXInteger('0123456789', radix=10, blocksize=10)

        # Vector 1: with tweak '9876543210'
        tweak = FFXInteger('9876543210', radix=10, blocksize=10)
        cipher_with_tweak = ffx_obj.encrypt(tweak, plaintext)

        # Vector 2: no tweak (tweak=0)
        # Need fresh encrypter to avoid any state issues
        ffx_obj2 = ffx.new(key.to_bytes(16), radix=10)
        cipher_no_tweak = ffx_obj2.encrypt(0, plaintext)

        # Verify both produce expected outputs
        assert str(cipher_with_tweak) == '6124200773', "Vector 1 mismatch"
        assert str(cipher_no_tweak) == '2433477484', "Vector 2 mismatch"
        
        # And they should be different
        assert cipher_with_tweak != cipher_no_tweak

    def test_alphanumeric_case_insensitive(self):
        """Vector 5: alphanumeric output can be compared case-insensitively."""
        key = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
        ffx_obj = ffx.new(key.to_bytes(16), radix=36)
        
        tweak = FFXInteger('TQF9J5QDAGSCSPB1', radix=36, blocksize=16)
        plaintext = FFXInteger('C4XPWULBM3M863JH', radix=36, blocksize=16)

        ciphertext = ffx_obj.encrypt(tweak, plaintext)

        # FFXInteger may return lowercase, NIST vectors are uppercase
        assert str(ciphertext).upper() == 'C8AQ3U846ZWH6QZP'
