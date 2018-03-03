# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
"""libolm Utility module.

This module contains utilities for olm.
It only contains the ed25519_verify function for signature verification.

Examples:
    alice = Account()

    signature = alice.sign(message)
    signing_key = alice.identity_keys()["ed25519"]

    assert signature
    assert signing_key

    Utility.ed25519_verify(signing_key, message, signature)

"""

from __future__ import unicode_literals

# pylint: disable=redefined-builtin,unused-import
from builtins import bytes

# pylint: disable=no-name-in-module
from _libolm import ffi, lib


class OlmVerifyError(Exception):
    """libolm signature verification exception."""


class Utility(object):
    # pylint: disable=too-few-public-methods
    """libolm Utility class."""

    _buf = None
    _utility = None

    @classmethod
    def _allocate(cls):
        # type: () -> None
        cls._buf = ffi.new("char[]", lib.olm_utility_size())
        cls._utility = lib.olm_utility(cls._buf)

    @classmethod
    def _check_error(cls, ret):
        # type: (int) -> None
        if ret != lib.olm_error():
            return

        raise OlmVerifyError("{}".format(
            ffi.string(lib.olm_utility_last_error(
                cls._utility)).decode("utf-8")))

    @classmethod
    def ed25519_verify(cls, key, message, signature):
        """Verify an ed25519 signature.

        Raises an OlmVerifyError if verification fails.
        Args:
            key(str): The ed25519 public key used for signing.
            message(str): The signed message.
            signature(bytes): The message signature.
        """
        if not cls._utility:
            cls._allocate()

        byte_key = bytes(key, "utf-8")
        byte_message = bytes(message, "utf-8")

        cls._check_error(
            lib.olm_ed25519_verify(cls._utility, byte_key, len(byte_key),
                                   byte_message, len(byte_message), signature,
                                   len(signature)))
