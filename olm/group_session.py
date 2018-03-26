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

class OlmGroupSessionError(Exception):
    """libolm Group session error exception."""


class InboundGroupSession(object):
    def __init__(self, session_key):
        # type: (str) -> None
        """Create a new inbound group session.

        Raises OlmGroupSessionError on failure. If there weren't enough random
        bytes for the session creation the error message for the exception will
        be NOT_ENOUGH_RANDOM.
        """
        pass


class OutboundGroupSession(object):
    def __init__(self):
        # type: () -> None
        """Create a new inbound group session.

        Raises OlmGroupSessionError on failure. If there weren't enough random
        bytes for the session creation the error message for the exception will
        be NOT_ENOUGH_RANDOM.
        """
        self._buf = ffi.new("char[]", lib.olm_outbound_group_session_size())
        self._session = lib.olm_outbound_group_session(self._buf)

        random_length = lib.olm_init_outbound_group_session_random_length(
            self._session
        )
        random = _URANDOM(random_length)
        random_buffer = ffi.new("char[]", random)

        lib.olm_init_outbound_group_session(
            self._session, random_buffer, random_length
        )

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
