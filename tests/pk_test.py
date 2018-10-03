import pytest

from olm import PkDecryption, PkDecryptionError, PkEncryption


class TestClass(object):
    def test_invalid_encryption(self):
        with pytest.raises(ValueError):
            PkEncryption("")

    def test_decrytion(self):
        decryption = PkDecryption()
        encryption = PkEncryption(decryption.public_key)
        plaintext = "It's a secret to everybody."
        message = encryption.encrypt(plaintext)
        decrypted_plaintext = decryption.decrypt(message)
        isinstance(decrypted_plaintext, str)
        assert plaintext == decrypted_plaintext

    def test_invalid_decrytion(self):
        decryption = PkDecryption()
        encryption = PkEncryption(decryption.public_key)
        plaintext = "It's a secret to everybody."
        message = encryption.encrypt(plaintext)
        message.ephermal_key = "?"
        with pytest.raises(PkDecryptionError):
            decryption.decrypt(message)
