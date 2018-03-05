# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
"""libolm Account module.

This module contains the account part of the olm library. It contains a single
Account class which handles the creation of new accounts as well as the storing
and restoring of them.

Examples:
    acc = Account()
    account.identity_keys()
    account.generate_one_time_keys(1)

"""

from __future__ import unicode_literals

import json
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


class OlmAccountError(Exception):
    """libolm Account error exception."""


class Account(object):
    """libolm Account class."""

    def __init__(self, buf=None, account=None):
        # type: (ffi.cdata, ffi.cdata) -> None
        """Create a new olm account.

        The contructor creates a new identity key pair unless the arguments buf
        and account are provided. The arguments should never be provided by the
        user, use from_pickle instead.

        Raises OlmAccountError on failure. If there weren't enough random bytes
        for the account creation the error message for the exception will be
        NOT_ENOUGH_RANDOM.
        """
        if buf and account:
            self._buf = buf
            self._account = account
            return

        self._buf, self._account = Account._allocate()
        self._create()

    @staticmethod
    def _allocate():
        # type: () -> Tuple[ffi.cdata, ffi.cdata]
        buf = ffi.new("char[]", lib.olm_account_size())
        account = lib.olm_account(buf)

        return buf, account

    def _create(self):
        # type: () -> None
        random_length = lib.olm_create_account_random_length(self._account)
        random = _URANDOM(random_length)
        random_buffer = ffi.new("char[]", random)

        self._check_error(
            lib.olm_create_account(self._account, random_buffer,
                                   random_length))

    def _check_error(self, ret):
        # type: (int) -> None
        Account._check_error_buf(self._account, ret)

    @staticmethod
    def _check_error_buf(account, ret):
        # type: (ffi.cdata, int) -> None
        if ret != lib.olm_error():
            return

        raise OlmAccountError("{}".format(
            ffi.string(lib.olm_account_last_error(account)).decode("utf-8")))

    def pickle(self, passphrase=""):
        # type: (Optional[str]) -> bytes
        """Store an olm account.

        Stores an account as a base64 string. Encrypts the account using the
        supplied passphrase. Returns a byte object containing the base64
        encoded string of the pickled account. Raises OlmAccountError on
        failure.

        Args:
            passphrase(str): The passphrase to be used to encrypt the account.
        """
        byte_key = bytes(passphrase, "utf-8")
        key_buffer = ffi.new("char[]", byte_key)

        pickle_length = lib.olm_pickle_account_length(self._account)
        pickle_buffer = ffi.new("char[]", pickle_length)

        self._check_error(
            lib.olm_pickle_account(self._account, key_buffer, len(byte_key),
                                   pickle_buffer, pickle_length))
        return ffi.unpack(pickle_buffer, pickle_length)

    @classmethod
    def from_pickle(cls, pickle, passphrase=""):
        # type: (bytes, Optional[str]) -> Account
        """Load an previously stored olm account.

        Loads an account from a pickled base64 string and returns an Account
        object. Decrypts the account using the supplied passphrase. Raises
        OlmAccountError on failure. If the passphrase doesn't match the one
        used to encrypt the account then the error message for the
        exception will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded
        then the error message will be "INVALID_BASE64".

        Args:
            passphrase(str): The passphrase used to encrypt the account.
            pickle(bytes): Base64 encoded byte string containing the pickled
                           account
        """
        byte_key = bytes(passphrase, "utf-8")
        key_buffer = ffi.new("char[]", byte_key)
        pickle_buffer = ffi.new("char[]", pickle)

        buf, account = Account._allocate()

        ret = lib.olm_unpickle_account(account, key_buffer, len(byte_key),
                                       pickle_buffer, len(pickle))
        Account._check_error_buf(account, ret)

        return cls(buf, account)

    def identity_keys(self):
        # type: () -> Dict[str, str]
        """Get the public identity keys of the account.

        Returns a dict containing the public identity keys of the account.
        Raises OlmAccountError on failure.
        """
        out_length = lib.olm_account_identity_keys_length(self._account)
        out_buffer = ffi.new("char[]", out_length)

        self._check_error(
            lib.olm_account_identity_keys(self._account, out_buffer,
                                          out_length))
        return json.loads(ffi.unpack(out_buffer, out_length))

    def sign(self, message):
        # type: (str) -> bytes
        """Signs a message with this account.

        Signs a message with the private ed25519 identity key of this account.
        Returns the signature.
        Raises OlmAccountError on failure.

        Args:
            message(str): The message to sign.
        """
        bytes_message = bytes(message, "utf-8")
        out_length = lib.olm_account_signature_length(self._account)
        message_buffer = ffi.new("char[]", bytes_message)
        out_buffer = ffi.new("char[]", out_length)

        self._check_error(
            lib.olm_account_sign(self._account, message_buffer,
                                 len(bytes_message), out_buffer, out_length))

        return ffi.unpack(out_buffer, out_length)

    def max_one_time_keys(self):
        # type: () -> int
        """Get the maximum number of one time keys the account can store."""
        return lib.olm_account_max_number_of_one_time_keys(self._account)

    def mark_keys_as_published(self):
        # type: () -> None
        """Mark the current set of one time keys as being published."""
        lib.olm_account_mark_keys_as_published(self._account)

    def generate_one_time_keys(self, count):
        # type: (int) -> None
        """Generate a number of new one time keys.

        If the total number of keys stored by this account exceeds
        max_one_time_keys() then the old keys are discarded.
        Raises OlmAccountError on error. If the number of random bytes is
        too small then the error message of the exception will be
        NOT_ENOUGH_RANDOM.

        Args:
            count(int): The number of keys to generate.
        """
        random_length = lib.olm_account_generate_one_time_keys_random_length(
            self._account, count)
        random = _URANDOM(random_length)
        random_buffer = ffi.new("char[]", random)
        self._check_error(
            lib.olm_account_generate_one_time_keys(
                self._account, count, random_buffer, random_length))

    def one_time_keys(self):
        # type: () -> Dict[str, Dict[str, str]]
        """Get the public one time keys of the account.

        Returns a dict containing the public identity keys of the account.
        Raises OlmAccountError on failure.
        """
        out_length = lib.olm_account_one_time_keys_length(self._account)
        out_buffer = ffi.new("char[]", out_length)

        self._check_error(
            lib.olm_account_one_time_keys(self._account, out_buffer,
                                          out_length))

        return json.loads(ffi.unpack(out_buffer, out_length))

    def clear(self):
        # type: () -> None
        """Clear the memory used to back this account.

        After clearing the account the account state is invalid and can't be
        reused. This method is called in the deconstructor of this class.
        """
        lib.olm_clear_account(self._account)
        self._account = None
        self._buf = None

    def __del__(self):
        # type: () -> None
        """Delete the account."""
        if self._account:
            self.clear()
