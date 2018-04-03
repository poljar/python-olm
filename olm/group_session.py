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
from builtins import bytes
from typing import Dict, Optional, Tuple

# pylint: disable=no-name-in-module
from _libolm import ffi, lib  # type: ignore

try:
    import secrets
    _URANDOM = secrets.token_bytes
except ImportError:  # pragma: no cover
    from os import urandom
    _URANDOM = urandom  # type: ignore


class OlmGroupSessionError(Exception):
    """libolm Group session error exception."""


class InboundGroupSession(object):
    def __init__(self, session_key=None, _buf=None, _session=None):
        # type: (str) -> None
        """Create a new inbound group session.

        Raises OlmGroupSessionError on failure. If there weren't enough random
        bytes for the session creation the error message for the exception will
        be NOT_ENOUGH_RANDOM.
        """
        if _buf and _session:
            self._buf = _buf
            self._session = _session
            return

        self._buf, self._session = InboundGroupSession._allocate()

        byte_session_key = bytes(session_key, "utf-8")

        key_buffer = ffi.new("char[]", byte_session_key)
        lib.olm_init_inbound_group_session(
            self._session, key_buffer, len(byte_session_key)
        )

    @staticmethod
    def _allocate():
        # type: () -> Tuple[ffi.cdata, ffi.cdata]
        buf = ffi.new("char[]", lib.olm_inbound_group_session_size())
        session = lib.olm_inbound_group_session(buf)

        return buf, session

    def pickle(self, passphrase=""):
        # type: (Optional[str]) -> bytes
        byte_passphrase = bytes(passphrase, "utf-8")

        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_length = lib.olm_pickle_inbound_group_session_length(
            self._session)
        pickle_buffer = ffi.new("char[]", pickle_length)

        lib.olm_pickle_inbound_group_session(
            self._session, passphrase_buffer, len(byte_passphrase),
            pickle_buffer, pickle_length
        )

        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # type: (bytes, Optional[str]) -> InboundGroupSession
        byte_passphrase = bytes(passphrase, "utf-8")
        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_buffer = ffi.new("char[]", pickle)

        buf, session = InboundGroupSession._allocate()

        ret = lib.olm_unpickle_inbound_group_session(
            session,
            passphrase_buffer,
            len(byte_passphrase),
            pickle_buffer,
            len(pickle)
        )
        InboundGroupSession._check_error_buf(session, ret)

        return cls(_buf=buf, _session=session)

    @staticmethod
    def _check_error_buf(session, ret):
        # type: (ffi.cdata, int) -> None
        if ret != lib.olm_error():
            return

        raise OlmGroupSessionError(
            "{}".format(
                ffi.string(
                    lib.olm_inbound_group_session_last_error(session)
                ).decode("utf-8")
            ))

    def _check_error(self, ret):
        InboundGroupSession._check_error_buf(self._session, ret)

    def decrypt(self, ciphertext):
        #type: (str) -> str
        byte_ciphertext = bytes(ciphertext, "utf-8")
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

        return ffi.unpack(
            plaintext_buffer,
            plaintext_length
        ).decode("utf-8")

    @property
    def id(self):
        # type: () -> str
        id_length = lib.olm_inbound_group_session_id_length(self._session)
        id_buffer = ffi.new("char[]", id_length)
        lib.olm_inbound_group_session_id(self._session, id_buffer, id_length)
        return ffi.unpack(id_buffer, id_length).decode("utf-8")

    @property
    def first_known_index(self):
        # type: () -> int
        return lib.olm_inbound_group_session_first_known_index(self._session)

    def export_session(self, message_index):
        # type: (int) -> str
        export_length = lib.olm_export_inbound_group_session_length(
            self._session)

        export_buffer = ffi.new("char[]", export_length)
        lib.olm_export_inbound_group_session(self._session, export_buffer,
                                             export_length, message_index)
        return ffi.unpack(export_buffer, export_length).decode("utf-8")


class OutboundGroupSession(object):
    def __init__(self, _buf=None, _session=None):
        # type: () -> None
        """Create a new inbound group session.

        Raises OlmGroupSessionError on failure. If there weren't enough random
        bytes for the session creation the error message for the exception will
        be NOT_ENOUGH_RANDOM.
        """
        if _buf and _session:
            self._buf = _buf
            self._session = _session
            return

        self._buf, self._session = OutboundGroupSession._allocate()

        random_length = lib.olm_init_outbound_group_session_random_length(
            self._session
        )
        random = _URANDOM(random_length)
        random_buffer = ffi.new("char[]", random)

        lib.olm_init_outbound_group_session(
            self._session, random_buffer, random_length
        )

    @staticmethod
    def _allocate():
        # type: () -> Tuple[ffi.cdata, ffi.cdata]
        buf = ffi.new("char[]", lib.olm_outbound_group_session_size())
        session = lib.olm_outbound_group_session(buf)

        return buf, session

    def pickle(self, passphrase=""):
        # type: (Optional[str]) -> bytes
        byte_passphrase = bytes(passphrase, "utf-8")
        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_length = lib.olm_pickle_outbound_group_session_length(
            self._session)
        pickle_buffer = ffi.new("char[]", pickle_length)

        lib.olm_pickle_outbound_group_session(
            self._session, passphrase_buffer, len(byte_passphrase),
            pickle_buffer, pickle_length
        )
        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # type: (bytes, Optional[str]) -> OutboundGroupSession
        byte_passphrase = bytes(passphrase, "utf-8")
        passphrase_buffer = ffi.new("char[]", byte_passphrase)
        pickle_buffer = ffi.new("char[]", pickle)

        buf, session = OutboundGroupSession._allocate()

        lib.olm_unpickle_outbound_group_session(
            session,
            passphrase_buffer,
            len(byte_passphrase),
            pickle_buffer,
            len(pickle)
        )

        return cls(buf, session)

    def encrypt(self, plaintext):
        # type: (str) -> str
        byte_plaintext = bytes(plaintext, "utf-8")

        message_length = lib.olm_group_encrypt_message_length(
            self._session, len(byte_plaintext)
        )

        message_buffer = ffi.new("char[]", message_length)

        plaintext_buffer = ffi.new("char[]", byte_plaintext)

        lib.olm_group_encrypt(
            self._session,
            plaintext_buffer, len(byte_plaintext),
            message_buffer, message_length,
        )
        return ffi.unpack(message_buffer, message_length).decode("utf-8")

    @property
    def id(self):
        # type: () -> str
        id_length = lib.olm_outbound_group_session_id_length(self._session)
        id_buffer = ffi.new("char[]", id_length)

        lib.olm_outbound_group_session_id(self._session, id_buffer, id_length)

        return ffi.unpack(id_buffer, id_length).decode("utf-8")

    @property
    def message_index(self):
        # type: () -> int
        return lib.olm_outbound_group_session_message_index(self._session)

    @property
    def session_key(self):
        # type: () -> str
        key_length = lib.olm_outbound_group_session_key_length(self._session)
        key_buffer = ffi.new("char[]", key_length)

        lib.olm_outbound_group_session_key(
            self._session,
            key_buffer,
            key_length
        )

        return ffi.unpack(key_buffer, key_length).decode("utf-8")
