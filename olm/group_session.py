# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
"""libolm Group session module.

This module contains the group session part of the Olm library. It contains two
classes for creating inbound and outbound group sessions.

Examples:
    >>> outbound = OutboundGroupSession()
    >>> InboundGroupSession(outbound.session_key)
"""

# pylint: disable=redefined-builtin,unused-import
from builtins import bytes, super
from typing import AnyStr, Optional, Tuple, Type

from future.utils import bytes_to_native_str

# pylint: disable=no-name-in-module
from _libolm import ffi, lib  # type: ignore

from ._compat import URANDOM, to_bytes
from ._finalize import track_for_finalization


def _clear_inbound_group_session(session):
    # type: (ffi.cdata) -> None
    lib.olm_clear_inbound_group_session(session)


def _clear_outbound_group_session(session):
    # type: (ffi.cdata) -> None
    lib.olm_clear_outbound_group_session(session)


class OlmGroupSessionError(Exception):
    """libolm Group session error exception."""


class InboundGroupSession(object):
    """Inbound group session for encrypted multiuser communication."""

    def __new__(
        cls,              # type: Type[InboundGroupSession]
        session_key=None  # type: Optional[str]
    ):
        # type: (...) -> InboundGroupSession
        obj = super().__new__(cls)
        obj._buf = ffi.new("char[]", lib.olm_inbound_group_session_size())
        obj._session = lib.olm_inbound_group_session(obj._buf)
        track_for_finalization(obj, obj._session, _clear_inbound_group_session)
        return obj

    def __init__(self, session_key):
        # type: (AnyStr) -> None
        """Create a new inbound group session.
        Start a new inbound group session, from a key exported from
        an outbound group session.

        Raises OlmGroupSessionError on failure. The error message of the
        exception will be "OLM_INVALID_BASE64" if the session key is not valid
        base64 and "OLM_BAD_SESSION_KEY" if the session key is invalid.
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
        """Store an inbound group session.

        Stores a group session as a base64 string. Encrypts the session using
        the supplied passphrase. Returns a byte object containing the base64
        encoded string of the pickled session.

        Args:
            passphrase(str, optional): The passphrase to be used to encrypt
                the session.
        """
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
        """Load a previously stored inbound group session.

        Loads an inbound group session from a pickled base64 string and returns
        an InboundGroupSession object. Decrypts the session using the supplied
        passphrase. Raises OlmSessionError on failure. If the passphrase
        doesn't match the one used to encrypt the session then the error
        message for the exception will be "BAD_ACCOUNT_KEY". If the base64
        couldn't be decoded then the error message will be "INVALID_BASE64".

        Args:
            pickle(bytes): Base64 encoded byte string containing the pickled
                session
            passphrase(str, optional): The passphrase used to encrypt the
                session
        """
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
        # type: (AnyStr) -> Tuple[str, int]
        """Decrypt a message

        Returns a tuple of the decrypted plain-text and the message index of
        the decrypted message or raises OlmGroupSessionError on failure.
        On failure the error message of the exception  will be:

        * OLM_INVALID_BASE64         if the message is not valid base64
        * OLM_BAD_MESSAGE_VERSION    if the message was encrypted with an
            unsupported version of the protocol
        * OLM_BAD_MESSAGE_FORMAT     if the message headers could not be
            decoded
        * OLM_BAD_MESSAGE_MAC        if the message could not be verified
        * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key
            corresponding to the message's index (i.e., it was sent before
            the session key was shared with us)

        Args:
            ciphertext(str): Base64 encoded ciphertext containing the encrypted
                message
        """
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
        )), message_index[0]

    @property
    def id(self):
        # type: () -> str
        """str: A base64 encoded identifier for this session."""
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
        """int: The first message index we know how to decrypt."""
        return lib.olm_inbound_group_session_first_known_index(self._session)

    def export_session(self, message_index):
        # type: (int) -> str
        """Export an inbound group session

        Export the base64-encoded ratchet key for this session, at the given
        index, in a format which can be used by import_session().

        Raises OlmGroupSessionError on failure. The error message for the
        exception will be:

        * OLM_UNKNOWN_MESSAGE_INDEX if we do not have a session key
            corresponding to the given index (ie, it was sent before the
            session key was shared with us)

        Args:
            message_index(int): The message index at which the session should
                be exported.
        """

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
        """Create an InboundGroupSession from an exported session key.

        Creates an InboundGroupSession with an previously exported session key,
        raises OlmGroupSessionError on failure. The error message for the
        exception will be:

        * OLM_INVALID_BASE64  if the session_key is not valid base64
        * OLM_BAD_SESSION_KEY if the session_key is invalid

        Args:
            session_key(str): The exported session key with which the inbound
                group session will be created
        """
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
    """Outbound group session for encrypted multiuser communication."""

    def __new__(cls):
        # type: (Type[OutboundGroupSession]) -> OutboundGroupSession
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
        """Create a new outbound group session.

        Start a new outbound group session. Raises OlmGroupSessionError on
        failure. If there weren't enough random bytes for the session creation
        the error message for the exception will be NOT_ENOUGH_RANDOM.
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
        """Store an outbound group session.

        Stores a group session as a base64 string. Encrypts the session using
        the supplied passphrase. Returns a byte object containing the base64
        encoded string of the pickled session.

        Args:
            passphrase(str, optional): The passphrase to be used to encrypt
                the session.
        """
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
        """Load a previously stored outbound group session.

        Loads an outbound group session from a pickled base64 string and
        returns an OutboundGroupSession object. Decrypts the session using the
        supplied passphrase. Raises OlmSessionError on failure. If the
        passphrase doesn't match the one used to encrypt the session then the
        error message for the exception will be "BAD_ACCOUNT_KEY". If the
        base64 couldn't be decoded then the error message will be
        "INVALID_BASE64".

        Args:
            pickle(bytes): Base64 encoded byte string containing the pickled
                session
            passphrase(str, optional): The passphrase used to encrypt the
        """
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
        """Encrypt a message.

        Returns the encrypted ciphertext.

        Args:
            plaintext(str): A string that will be encrypted using the group
                session.
        """
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
        """str: A base64 encoded identifier for this session."""
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
        """int: The current message index of the session.

        Each message is encrypted with an increasing index. This is the index
        for the next message.
        """
        return lib.olm_outbound_group_session_message_index(self._session)

    @property
    def session_key(self):
        # type: () -> str
        """The base64-encoded current ratchet key for this session.

        Each message is encrypted with a different ratchet key. This function
        returns the ratchet key that will be used for the next message.
        """
        key_length = lib.olm_outbound_group_session_key_length(self._session)
        key_buffer = ffi.new("char[]", key_length)

        ret = lib.olm_outbound_group_session_key(
            self._session,
            key_buffer,
            key_length
        )
        self._check_error(ret)

        return bytes_to_native_str(ffi.unpack(key_buffer, key_length))
