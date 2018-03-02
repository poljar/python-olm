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
PATH = os.path.dirname(__file__)

ffibuilder.set_source(
    "_libolm",
    r"""
        #include <olm/olm.h>
    """, libraries=["olm"])

with open(os.path.join(PATH, "olm.h")) as f:
    ffibuilder.cdef(f.read(), override=True)

# ffibuilder.cdef("""
#     typedef struct OlmAccount OlmAccount;

#     OlmAccount * olm_account(void * memory);
#     size_t olm_account_size();
#     size_t olm_create_account_random_length(OlmAccount * account);
#     size_t olm_create_account(
#         OlmAccount * account, void * random, size_t random_length
#     );

#     size_t olm_account_identity_keys_length(
#         OlmAccount * account
#     );

#     size_t olm_account_identity_keys(
#         OlmAccount * account,
#         void * identity_keys, size_t identity_key_length
#     );

#     size_t olm_pickle_account(
#         OlmAccount * account,
#         void const * key, size_t key_length,
#         void * pickled, size_t pickled_length
#     );

#     size_t olm_pickle_account_length(
#         OlmAccount * account
#     );

#     size_t olm_unpickle_account(
#         OlmAccount * account,
#         void const * key, size_t key_length,
#         void * pickled, size_t pickled_length
#     );

#     size_t olm_account_signature_length(
#         OlmAccount * account
#     );

#     size_t olm_account_sign(
#         OlmAccount * account,
#         void const * message, size_t message_length,
#         void * signature, size_t signature_length
#     );

#     size_t olm_account_generate_one_time_keys_random_length(
#         OlmAccount * account,
#         size_t number_of_keys
#     );

#     size_t olm_account_generate_one_time_keys(
#         OlmAccount * account,
#         size_t number_of_keys,
#         void * random, size_t random_length
#     );

#     size_t olm_account_max_number_of_one_time_keys(
#         OlmAccount * account
#     );

#     size_t olm_account_mark_keys_as_published(
#         OlmAccount * account
#     );

#     size_t olm_account_one_time_keys_length(
#         OlmAccount * account
#     );

#     size_t olm_account_one_time_keys(
#         OlmAccount * account,
#         void * one_time_keys, size_t one_time_keys_length
#     );

#     size_t olm_clear_account(
#         OlmAccount * account
#     );

#     size_t olm_error();
#     const char * olm_account_last_error(
#         OlmAccount * account
#     );

#     void olm_get_library_version(
#         uint8_t *major, uint8_t *minor, uint8_t *patch
#     );
# """)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
