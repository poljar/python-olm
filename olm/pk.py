# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
"""libolm PK module.

This module contains the PK part of the Olm library.

Examples:
"""

from builtins import super
from typing import AnyStr, Type
from future.utils import bytes_to_native_str

from _libolm import ffi, lib  # type: ignore
from ._finalize import track_for_finalization
from ._compat import URANDOM, to_bytes


class PkEncryptionError(Exception):
    """libolm Pk encryption exception."""


class PkDecryptionError(Exception):
    """libolm Pk decryption exception."""


def _clear_pk_encryption(pk_struct):
    lib.olm_clear_pk_encryption(pk_struct)


class PkMessage(object):
    def __init__(self, ephermal_key, mac, ciphertext):
        # type: (str, str, str) -> None
        self.ephermal_key = ephermal_key
        self.mac = mac
        self.ciphertext = ciphertext


class PkEncryption(object):
    def __init__(self, recipient_key):
        # type: (AnyStr) -> None
        if not recipient_key:
            raise ValueError("Recipient key can't be empty")

        self._buf = ffi.new("char[]", lib.olm_pk_encryption_size())
        self._pk_encryption = lib.olm_pk_encryption(self._buf)
        track_for_finalization(self, self._pk_encryption, _clear_pk_encryption)

        byte_key = to_bytes(recipient_key)
        lib.olm_pk_encryption_set_recipient_key(
            self._pk_encryption,
            byte_key,
            len(byte_key)
        )

    def _check_error(self, ret):  # pragma: no cover
        # type: (int) -> None
        if ret != lib.olm_error():
            return

        last_error = bytes_to_native_str(
            ffi.string(lib.olm_pk_encryption_last_error(self._pk_encryption)))

        raise PkEncryptionError(last_error)

    def encrypt(self, plaintext):
        # type: (AnyStr) -> PkMessage
        byte_plaintext = to_bytes(plaintext)

        r_length = lib.olm_pk_encrypt_random_length(self._pk_encryption)
        random = URANDOM(r_length)
        random_buffer = ffi.new("char[]", random)

        ciphertext_length = lib.olm_pk_ciphertext_length(
            self._pk_encryption, len(byte_plaintext)
        )
        ciphertext = ffi.new("char[]", ciphertext_length)

        mac_length = lib.olm_pk_mac_length(self._pk_encryption)
        mac = ffi.new("char[]", mac_length)

        ephermal_key_size = lib.olm_pk_key_length()
        ephermal_key = ffi.new("char[]", ephermal_key_size)

        ret = lib.olm_pk_encrypt(
            self._pk_encryption,
            byte_plaintext, len(byte_plaintext),
            ciphertext, ciphertext_length,
            mac, mac_length,
            ephermal_key, ephermal_key_size,
            random_buffer, r_length
        )
        self._check_error(ret)

        message = PkMessage(
            bytes_to_native_str(
                ffi.unpack(ephermal_key, ephermal_key_size)),
            bytes_to_native_str(
                ffi.unpack(mac, mac_length)),
            bytes_to_native_str(
                ffi.unpack(ciphertext, ciphertext_length))
        )
        return message


def _clear_pk_decryption(pk_struct):
    lib.olm_clear_pk_decryption(pk_struct)


class PkDecryption(object):
    def __new__(cls):
        # type: (Type[PkDecryption]) -> PkDecryption
        obj = super().__new__(cls)
        obj._buf = ffi.new("char[]", lib.olm_pk_decryption_size())
        obj._pk_decryption = lib.olm_pk_decryption(obj._buf)
        obj.public_key = None
        track_for_finalization(obj, obj._pk_decryption, _clear_pk_decryption)
        return obj

    def __init__(self):
        if False:  # pragma: no cover
            self._pk_decryption = self._pk_decryption  # type: ffi.cdata

        random_length = lib.olm_pk_generate_key_random_length()
        random = URANDOM(random_length)
        random_buffer = ffi.new("char[]", random)

        key_length = lib.olm_pk_key_length()
        key_buffer = ffi.new("char[]", key_length)

        ret = lib.olm_pk_generate_key(
            self._pk_decryption,
            key_buffer, key_length,
            random_buffer, random_length
        )
        self._check_error(ret)
        self.public_key = bytes_to_native_str(ffi.unpack(
            key_buffer,
            key_length
        ))

    def _check_error(self, ret):
        # type: (int) -> None
        if ret != lib.olm_error():
            return

        last_error = bytes_to_native_str(
            ffi.string(lib.olm_pk_decryption_last_error(self._pk_decryption)))

        raise PkDecryptionError(last_error)

    def pickle(self, passphrase=""):
        # type: (str) -> bytes
        byte_key = to_bytes(passphrase)
        key_buffer = ffi.new("char[]", byte_key)

        pickle_length = lib.olm_pickle_pk_decryption_length(
            self._pk_decryption
        )
        pickle_buffer = ffi.new("char[]", pickle_length)

        ret = lib.olm_pickle_pk_decryption(
            self._pk_decryption,
            key_buffer, len(byte_key),
            pickle_buffer, pickle_length
        )
        self._check_error(ret)

        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # types: (bytes, str) -> PkDecryption
        if not pickle:
            raise ValueError("Pickle can't be empty")

        byte_key = to_bytes(passphrase)
        key_buffer = ffi.new("char[]", byte_key)
        pickle_buffer = ffi.new("char[]", pickle)

        pubkey_length = lib.olm_pk_key_length()
        pubkey_buffer = ffi.new("char[]", pubkey_length)

        obj = cls.__new__(cls)

        ret = lib.olm_unpickle_pk_decryption(
            obj._pk_decryption,
            key_buffer, len(byte_key),
            pickle_buffer, len(pickle),
            pubkey_buffer, pubkey_length)

        obj._check_error(ret)

        obj.public_key = bytes_to_native_str(ffi.unpack(
            pubkey_buffer,
            pubkey_length
        ))

        return obj

    def decrypt(self, message):
        # type (PkMessage) -> str
        ephermal_key = to_bytes(message.ephermal_key)
        ephermal_key_size = len(ephermal_key)

        mac = to_bytes(message.mac)
        mac_length = len(mac)

        ciphertext = to_bytes(message.ciphertext)
        ciphertext_length = len(ciphertext)

        max_plaintext_length = lib.olm_pk_max_plaintext_length(
            self._pk_decryption,
            ciphertext_length
        )
        plaintext = ffi.new("char[]", max_plaintext_length)

        ret = lib.olm_pk_decrypt(
            self._pk_decryption,
            ephermal_key, ephermal_key_size,
            mac, mac_length,
            ciphertext, ciphertext_length,
            plaintext, max_plaintext_length)
        self._check_error(ret)

        unpacked_plaintext = (ffi.unpack(
            plaintext,
            ret
        ))

        return bytes_to_native_str(unpacked_plaintext)
