# -*- coding: utf-8 -*-
# libolm python bindings
# Copyright © 2015-2017 OpenMarket Ltd
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>

try:
    import secrets
    URANDOM = secrets.token_bytes  # pragma: no cover
except ImportError:  # pragma: no cover
    from os import urandom
    URANDOM = urandom  # type: ignore
