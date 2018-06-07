# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
"""libolm Session module.

This module contains the olm session part of the olm library.

Examples:
    alice = Account()
    bob = Account()
    bob.generate_one_time_keys(1)
    id_key = bob.identity_keys['curve25519']
    one_time = list(bob.one_time_keys["curve25519"].values())[0]
    session = OutboundSession(alice, id_key, one_time)
    s = OutboundSession(alice, id_key, one_time)

"""

from __future__ import unicode_literals

# pylint: disable=redefined-builtin,unused-import
from builtins import bytes
from typing import Dict, Optional, Tuple

# pylint: disable=no-name-in-module
from _libolm import ffi, lib  # type: ignore
from .finalize import track_for_finalization
from ._compat import URANDOM

# This is imported only for type checking purposes
if False:
    from .account import Account  # pragma: no cover


class OlmSessionError(Exception):
    """libolm Session exception."""


class _OlmMessage():
    def __init__(self, ciphertext, message_type):
        # type: (str, ffi.cdata) -> None
        self.ciphertext = ciphertext
        self.message_type = message_type

    def __str__(self):
        # type: () -> str
        type_to_prefix = {
            lib.OLM_MESSAGE_TYPE_PRE_KEY: "PRE_KEY",
            lib.OLM_MESSAGE_TYPE_MESSAGE: "MESSAGE"
        }

        prefix = type_to_prefix[self.message_type]
        return "{} {}".format(prefix, self.ciphertext)


class OlmPreKeyMessage(_OlmMessage):
    def __init__(self, ciphertext):
        # type: (str) -> None
        _OlmMessage.__init__(self, ciphertext, lib.OLM_MESSAGE_TYPE_PRE_KEY)

    def __repr__(self):
        # type: () -> str
        return "OlmPreKeyMessage({})".format(self.ciphertext)


class OlmMessage(_OlmMessage):
    def __init__(self, ciphertext):
        # type: (str) -> None
        _OlmMessage.__init__(self, ciphertext, lib.OLM_MESSAGE_TYPE_MESSAGE)

    def __repr__(self):
        # type: () -> str
        return "OlmMessage({})".format(self.ciphertext)


def _clear_session(session):
    lib.olm_clear_session(session)


class Session():
    """libolm Session class."""

    def __init__(self):
        # type: () -> None
        self._buf = ffi.new("char[]", lib.olm_session_size())
        self._session = lib.olm_session(self._buf)
        track_for_finalization(self, self._session, _clear_session)

    def _check_error(self, ret):
        # type: (int) -> None
        if ret != lib.olm_error():
            return

        last_error = ffi.string(
            lib.olm_session_last_error(self._session)
        ).decode("utf-8")

        raise OlmSessionError(last_error)

    def pickle(self, passphrase=""):
        # type: (Optional[str]) -> bytes
        """Store a olm session.

        Stores a session as a base64 string. Encrypts the session using the
        supplied passphrase. Returns a byte object containing the base64
        encoded string of the pickled session. Raises OlmSessionError on
        failure.

        Args:
            passphrase(str): The passphrase to be used to encrypt the session.
        """
        byte_key = bytes(passphrase, "utf-8") if passphrase else b""
        key_buffer = ffi.new("char[]", byte_key)

        pickle_length = lib.olm_pickle_session_length(self._session)
        pickle_buffer = ffi.new("char[]", pickle_length)

        self._check_error(
            lib.olm_pickle_session(self._session, key_buffer, len(byte_key),
                                   pickle_buffer, pickle_length))
        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # type: (bytes, Optional[str]) -> Session
        """Load an previously stored olm session.

        Loads a session from a pickled base64 string and returns a Session
        object. Decrypts the session using the supplied passphrase. Raises
        OlmSessionError on failure. If the passphrase doesn't match the one
        used to encrypt the session then the error message for the
        exception will be "BAD_SESSION_KEY". If the base64 couldn't be decoded
        then the error message will be "INVALID_BASE64".

        Args:
            passphrase(str): The passphrase used to encrypt the session.
            pickle(bytes): Base64 encoded byte string containing the pickled
                           session
        """
        byte_key = bytes(passphrase, "utf-8") if passphrase else b""
        key_buffer = ffi.new("char[]", byte_key)
        pickle_buffer = ffi.new("char[]", pickle)

        session = cls()

        ret = lib.olm_unpickle_session(session._session, key_buffer,
                                       len(byte_key), pickle_buffer,
                                       len(pickle))
        session._check_error(ret)

        return session

    def encrypt(self, plaintext):
        # type: (str) -> _OlmMessage
        byte_plaintext = bytes(plaintext, "utf-8")
        r_length = lib.olm_encrypt_random_length(self._session)
        random = URANDOM(r_length)
        random_buffer = ffi.new("char[]", random)

        message_type = lib.olm_encrypt_message_type(self._session)

        self._check_error(message_type)

        ciphertext_length = lib.olm_encrypt_message_length(
            self._session, len(plaintext)
        )
        ciphertext_buffer = ffi.new("char[]", ciphertext_length)

        plaintext_buffer = ffi.new("char[]", byte_plaintext)

        self._check_error(lib.olm_encrypt(
            self._session,
            plaintext_buffer, len(byte_plaintext),
            random_buffer, r_length,
            ciphertext_buffer, ciphertext_length,
        ))

        if message_type == lib.OLM_MESSAGE_TYPE_PRE_KEY:
            return OlmPreKeyMessage(
                ffi.unpack(ciphertext_buffer,
                           ciphertext_length).decode("utf-8"))
        elif message_type == lib.OLM_MESSAGE_TYPE_MESSAGE:
            return OlmMessage(
                ffi.unpack(ciphertext_buffer,
                           ciphertext_length).decode("utf-8"))
        else:  # pragma: no cover
            raise ValueError("Unknown message type")

    def decrypt(self, message):
        # type: (_OlmMessage) -> str
        byte_ciphertext = bytes(message.ciphertext, "utf-8")
        ciphertext_buffer = ffi.new("char[]", byte_ciphertext)

        max_plaintext_length = lib.olm_decrypt_max_plaintext_length(
            self._session, message.message_type, ciphertext_buffer,
            len(message.ciphertext)
        )
        plaintext_buffer = ffi.new("char[]", max_plaintext_length)
        ciphertext_buffer = ffi.new("char[]", byte_ciphertext)
        plaintext_length = lib.olm_decrypt(
            self._session, message.message_type, ciphertext_buffer,
            len(byte_ciphertext), plaintext_buffer, max_plaintext_length
        )
        self._check_error(plaintext_length)
        return ffi.unpack(plaintext_buffer, plaintext_length).decode("utf-8")

    @property
    def id(self):
        # type () -> str
        id_length = lib.olm_session_id_length(self._session)
        id_buffer = ffi.new("char[]", id_length)

        self._check_error(
            lib.olm_session_id(self._session, id_buffer, id_length)
        )
        return ffi.unpack(id_buffer, id_length).decode("utf-8")

    def matches(self, message, identity_key=None):
        # type: (_OlmMessage, Optional[str]) -> bool
        ret = None
        byte_ciphertext = bytes(message.ciphertext, "utf-8")
        message_buffer = ffi.new("char[]", byte_ciphertext)

        if identity_key:
            byte_id_key = bytes(identity_key, "utf-8")
            identity_key_buffer = ffi.new("char[]", byte_id_key)

            ret = lib.olm_matches_inbound_session_from(
                self._session,
                identity_key_buffer, len(byte_id_key),
                message_buffer, len(byte_ciphertext)
            )

        else:
            ret = lib.olm_matches_inbound_session(
                self._session,
                message_buffer, len(message.ciphertext))

        self._check_error(ret)

        return bool(ret)


class InboundSession(Session):
    def __init__(self, account, message, identity_key=None):
        # type: (Account, _OlmMessage, Optional[str]) -> None
        """Create a new inbound olm session.

        Raises OlmSessionError on failure. If there weren't enough random bytes
        for the session creation the error message for the exception will be
        NOT_ENOUGH_RANDOM.
        """
        Session.__init__(self)
        message_buffer = ffi.new("char[]", bytes(message.ciphertext, "utf-8"))

        if identity_key:
            byte_id_key = bytes(identity_key, "utf-8")
            identity_key_buffer = ffi.new("char[]", byte_id_key)
            self._check_error(lib.olm_create_inbound_session_from(
                self._session,
                account._account,
                identity_key_buffer, len(byte_id_key),
                message_buffer, len(message.ciphertext)
            ))
        else:
            self._check_error(lib.olm_create_inbound_session(
                self._session,
                account._account,
                message_buffer, len(message.ciphertext)
            ))


class OutboundSession(Session):
    def __init__(self, account, identity_key, one_time_key):
        # type: (Account, str, str) -> None
        """Create a new outbound olm session.

        Raises OlmSessionError on failure. If there weren't enough random bytes
        for the session creation the error message for the exception will be
        NOT_ENOUGH_RANDOM.
        """
        Session.__init__(self)

        byte_id_key = bytes(identity_key, "utf-8")
        byte_one_time = bytes(one_time_key, "utf-8")

        session_random_length = lib.olm_create_outbound_session_random_length(
            self._session)

        random = URANDOM(session_random_length)
        random_buffer = ffi.new("char[]", random)
        identity_key_buffer = ffi.new("char[]", byte_id_key)
        one_time_key_buffer = ffi.new("char[]", byte_one_time)

        self._check_error(lib.olm_create_outbound_session(
            self._session,
            account._account,
            identity_key_buffer, len(byte_id_key),
            one_time_key_buffer, len(byte_one_time),
            random_buffer, session_random_length
        ))
