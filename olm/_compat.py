# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>

from builtins import bytes, str
from typing import AnyStr

try:
    import secrets
    URANDOM = secrets.token_bytes  # pragma: no cover
except ImportError:  # pragma: no cover
    from os import urandom
    URANDOM = urandom  # type: ignore


def to_bytes(string):
    # type: (AnyStr) -> bytes
    if isinstance(string, bytes):
        return string
    elif isinstance(string, str):
        return bytes(string, "utf-8")

    raise TypeError("Invalid type {}".format(type(string)))

def to_bytearray(string):
    # type: (AnyStr) -> bytes
    if isinstance(string, bytes):
        return bytearray(string)
    elif isinstance(string, str):
        return bytearray(string, "utf-8")

    raise TypeError("Invalid type {}".format(type(string)))
