# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
"""libolm Group session module.

This module contains the group session of the olm library. It contains a single
Account class which handles the creation of new accounts as well as the storing
and restoring of them.

Examples:
    acc = Account()
    account.identity_keys()
    account.generate_one_time_keys(1)

"""

from __future__ import unicode_literals

# pylint: disable=redefined-builtin,unused-import
from builtins import bytes, super
from future.utils import bytes_to_native_str
from typing import Optional, AnyStr

# pylint: disable=no-name-in-module
from _libolm import ffi, lib  # type: ignore

from ._compat import URANDOM, to_bytes
from .finalize import track_for_finalization


def _clear_inbound_group_session(session):
    lib.olm_clear_inbound_group_session(session)


def _clear_outbound_group_session(session):
    lib.olm_clear_outbound_group_session(session)


class OlmGroupSessionError(Exception):
    """libolm Group session error exception."""


class InboundGroupSession(object):
    def __new__(cls, session_key=None):
        obj = super().__new__(cls)
        obj._buf = ffi.new("char[]", lib.olm_inbound_group_session_size())
        obj._session = lib.olm_inbound_group_session(obj._buf)
        track_for_finalization(obj, obj._session, _clear_inbound_group_session)
        return obj

    def __init__(self, session_key):
        # type: (AnyStr) -> None
        """Create a new inbound group session.

        Raises OlmGroupSessionError on failure. If there weren't enough random
        bytes for the session creation the error message for the exception will
        be NOT_ENOUGH_RANDOM.
        """
        if False:  # pragma: no cover
            self._session = self._session  # type: ffi.cdata

        byte_session_key = to_bytes(session_key)

        key_buffer = ffi.new("char[]", byte_session_key)
        ret = lib.olm_init_inbound_group_session(
            self._session, key_buffer, len(byte_session_key)
        )
        self._check_error(ret)

    def pickle(self, passphrase=""):
        # type: (Optional[str]) -> bytes
        byte_passphrase = bytes(passphrase, "utf-8") if passphrase else b""

        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_length = lib.olm_pickle_inbound_group_session_length(
            self._session)
        pickle_buffer = ffi.new("char[]", pickle_length)

        ret = lib.olm_pickle_inbound_group_session(
            self._session, passphrase_buffer, len(byte_passphrase),
            pickle_buffer, pickle_length
        )

        self._check_error(ret)

        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # type: (bytes, Optional[str]) -> InboundGroupSession
        if not pickle:
            raise ValueError("Pickle can't be empty")

        byte_passphrase = bytes(passphrase, "utf-8") if passphrase else b""
        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_buffer = ffi.new("char[]", pickle)

        obj = cls.__new__(cls)

        ret = lib.olm_unpickle_inbound_group_session(
            obj._session,
            passphrase_buffer,
            len(byte_passphrase),
            pickle_buffer,
            len(pickle)
        )
        obj._check_error(ret)

        return obj

    def _check_error(self, ret):
        # type: (int) -> None
        if ret != lib.olm_error():
            return

        last_error = bytes_to_native_str(ffi.string(
            lib.olm_inbound_group_session_last_error(self._session)))

        raise OlmGroupSessionError(last_error)

    def decrypt(self, ciphertext):
        # type: (AnyStr) -> str
        if not ciphertext:
            raise ValueError("Ciphertext can't be empty.")

        byte_ciphertext = to_bytes(ciphertext)

        ciphertext_buffer = ffi.new("char[]", byte_ciphertext)

        max_plaintext_length = lib.olm_group_decrypt_max_plaintext_length(
            self._session, ciphertext_buffer, len(byte_ciphertext)
        )
        plaintext_buffer = ffi.new("char[]", max_plaintext_length)
        ciphertext_buffer = ffi.new("char[]", byte_ciphertext)

        message_index = ffi.new("uint32_t*")
        plaintext_length = lib.olm_group_decrypt(
            self._session, ciphertext_buffer, len(byte_ciphertext),
            plaintext_buffer, max_plaintext_length,
            message_index
        )

        self._check_error(plaintext_length)

        return bytes_to_native_str(ffi.unpack(
            plaintext_buffer,
            plaintext_length
        ))

    @property
    def id(self):
        # type: () -> str
        id_length = lib.olm_inbound_group_session_id_length(self._session)
        id_buffer = ffi.new("char[]", id_length)
        ret = lib.olm_inbound_group_session_id(
            self._session,
            id_buffer,
            id_length
        )
        self._check_error(ret)
        return bytes_to_native_str(ffi.unpack(id_buffer, id_length))

    @property
    def first_known_index(self):
        # type: () -> int
        return lib.olm_inbound_group_session_first_known_index(self._session)

    def export_session(self, message_index):
        # type: (int) -> str
        export_length = lib.olm_export_inbound_group_session_length(
            self._session)

        export_buffer = ffi.new("char[]", export_length)
        ret = lib.olm_export_inbound_group_session(
            self._session,
            export_buffer,
            export_length,
            message_index
        )
        self._check_error(ret)
        return bytes_to_native_str(ffi.unpack(export_buffer, export_length))

    @classmethod
    def import_session(cls, session_key):
        # type: (AnyStr) -> InboundGroupSession
        obj = cls.__new__(cls)

        byte_session_key = to_bytes(session_key)

        key_buffer = ffi.new("char[]", byte_session_key)
        ret = lib.olm_import_inbound_group_session(
            obj._session,
            key_buffer,
            len(byte_session_key)
        )
        obj._check_error(ret)

        return obj


class OutboundGroupSession(object):
    def __new__(cls):
        obj = super().__new__(cls)
        obj._buf = ffi.new("char[]", lib.olm_outbound_group_session_size())
        obj._session = lib.olm_outbound_group_session(obj._buf)
        track_for_finalization(
            obj,
            obj._session,
            _clear_outbound_group_session
        )
        return obj

    def __init__(self):
        # type: () -> None
        """Create a new inbound group session.

        Raises OlmGroupSessionError on failure. If there weren't enough random
        bytes for the session creation the error message for the exception will
        be NOT_ENOUGH_RANDOM.
        """
        if False:  # pragma: no cover
            self._session = self._session  # type: ffi.cdata

        random_length = lib.olm_init_outbound_group_session_random_length(
            self._session
        )
        random = URANDOM(random_length)
        random_buffer = ffi.new("char[]", random)

        ret = lib.olm_init_outbound_group_session(
            self._session, random_buffer, random_length
        )
        self._check_error(ret)

    def _check_error(self, ret):
        # type: (int) -> None
        if ret != lib.olm_error():
            return

        last_error = bytes_to_native_str(ffi.string(
            lib.olm_outbound_group_session_last_error(self._session)
        ))

        raise OlmGroupSessionError(last_error)

    def pickle(self, passphrase=""):
        # type: (Optional[str]) -> bytes
        byte_passphrase = bytes(passphrase, "utf-8") if passphrase else b""
        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_length = lib.olm_pickle_outbound_group_session_length(
            self._session)
        pickle_buffer = ffi.new("char[]", pickle_length)

        ret = lib.olm_pickle_outbound_group_session(
            self._session, passphrase_buffer, len(byte_passphrase),
            pickle_buffer, pickle_length
        )
        self._check_error(ret)
        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # type: (bytes, Optional[str]) -> OutboundGroupSession
        if not pickle:
            raise ValueError("Pickle can't be empty")

        byte_passphrase = bytes(passphrase, "utf-8") if passphrase else b""
        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_buffer = ffi.new("char[]", pickle)

        obj = cls.__new__(cls)

        ret = lib.olm_unpickle_outbound_group_session(
            obj._session,
            passphrase_buffer,
            len(byte_passphrase),
            pickle_buffer,
            len(pickle)
        )
        obj._check_error(ret)

        return obj

    def encrypt(self, plaintext):
        # type: (AnyStr) -> str
        byte_plaintext = to_bytes(plaintext)
        message_length = lib.olm_group_encrypt_message_length(
            self._session, len(byte_plaintext)
        )

        message_buffer = ffi.new("char[]", message_length)

        plaintext_buffer = ffi.new("char[]", byte_plaintext)

        ret = lib.olm_group_encrypt(
            self._session,
            plaintext_buffer, len(byte_plaintext),
            message_buffer, message_length,
        )
        self._check_error(ret)
        return bytes_to_native_str(ffi.unpack(message_buffer, message_length))

    @property
    def id(self):
        # type: () -> str
        id_length = lib.olm_outbound_group_session_id_length(self._session)
        id_buffer = ffi.new("char[]", id_length)

        ret = lib.olm_outbound_group_session_id(
            self._session,
            id_buffer,
            id_length
        )
        self._check_error(ret)

        return bytes_to_native_str(ffi.unpack(id_buffer, id_length))

    @property
    def message_index(self):
        # type: () -> int
        return lib.olm_outbound_group_session_message_index(self._session)

    @property
    def session_key(self):
        # type: () -> str
        key_length = lib.olm_outbound_group_session_key_length(self._session)
        key_buffer = ffi.new("char[]", key_length)

        ret = lib.olm_outbound_group_session_key(
            self._session,
            key_buffer,
            key_length
        )
        self._check_error(ret)

        return bytes_to_native_str(ffi.unpack(key_buffer, key_length))
