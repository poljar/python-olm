import base64
import hashlib
from builtins import bytes

import pytest
from future.utils import bytes_to_native_str
from hypothesis import given
from hypothesis.strategies import text

from olm import OlmSasError, Sas, sha256
from olm._compat import to_bytes

MESSAGE = "Test message"
EXTRA_INFO = "extra_info"


class TestClass(object):
    def test_sas_creation(self):
        sas = Sas()
        assert sas.pubkey

    def test_other_key_setting(self):
        sas_alice = Sas()
        sas_bob = Sas()

        assert not sas_alice.other_key_set
        sas_alice.set_their_pubkey(sas_bob.pubkey)
        assert sas_alice.other_key_set

    def test_bytes_generating(self):
        sas_alice = Sas()
        sas_bob = Sas(sas_alice.pubkey)

        assert sas_bob.other_key_set

        with pytest.raises(OlmSasError):
            sas_alice.generate_bytes(EXTRA_INFO, 5)

        sas_alice.set_their_pubkey(sas_bob.pubkey)

        with pytest.raises(ValueError):
            sas_alice.generate_bytes(EXTRA_INFO, 0)

        alice_bytes = sas_alice.generate_bytes(EXTRA_INFO, 5)
        bob_bytes = sas_bob.generate_bytes(EXTRA_INFO, 5)

        assert alice_bytes == bob_bytes

    def test_mac_generating(self):
        sas_alice = Sas()
        sas_bob = Sas()

        with pytest.raises(OlmSasError):
            sas_alice.calculate_mac(MESSAGE, EXTRA_INFO)

        sas_alice.set_their_pubkey(sas_bob.pubkey)
        sas_bob.set_their_pubkey(sas_alice.pubkey)

        alice_mac = sas_alice.calculate_mac(MESSAGE, EXTRA_INFO)
        bob_mac = sas_bob.calculate_mac(MESSAGE, EXTRA_INFO)

        assert alice_mac == bob_mac

    def test_cross_language_mac(self):
        """Test MAC generating with a predefined key pair.

        This test imports a private and public key from the C test and checks
        if we are getting the same MAC that the C code calculated.
        """
        alice_private = [
            0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
            0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
            0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
            0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A
        ]

        bob_key = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08"
        message = "Hello world!"
        extra_info = "MAC"
        expected_mac = "2nSMTXM+TStTU3RUVTNSVVZUTlNWVlpVVGxOV1ZscFY"

        sas_alice = Sas()
        sas_alice._create_sas(bytes(alice_private), 32)
        sas_alice.set_their_pubkey(bob_key)

        alice_mac = sas_alice.calculate_mac(message, extra_info)

        assert alice_mac == expected_mac

    @given(text(), text())
    def test_sha256(self, input1, input2):
        first_hash = sha256(input1)
        second_hash = sha256(input2)

        hashlib_hash = base64.b64encode(
            hashlib.sha256(to_bytes(input1)).digest()
        )

        hashlib_hash = bytes_to_native_str(hashlib_hash[:-1])

        if input1 == input2:
            assert first_hash == second_hash
        else:
            assert first_hash != second_hash

        assert hashlib_hash == first_hash
