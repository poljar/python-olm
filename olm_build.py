# -*- coding: utf-8 -*-

# libolm python bindings
# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import unicode_literals

import os

from cffi import FFI

ffibuilder = FFI()
PATH = os.path.dirname(os.path.abspath(__file__))


ffibuilder.set_source(
    "_libolm",
    r"""
        #include <olm/olm.h>
        #include <olm/inbound_group_session.h>
        #include <olm/outbound_group_session.h>
        #include <olm/pk.h>
    """, libraries=["olm"])

with open(os.path.join(PATH, "include/olm/olm.h")) as f:
    ffibuilder.cdef(f.read(), override=True)

with open(os.path.join(PATH, "include/olm/pk.h")) as f:
    ffibuilder.cdef(f.read(), override=True)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
