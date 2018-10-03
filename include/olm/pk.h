/* Copyright 2018 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

typedef struct OlmPkEncryption OlmPkEncryption;

/* The size of an encryption object in bytes */
size_t olm_pk_encryption_size(void);

/** Initialise an encryption object using the supplied memory
 *  The supplied memory must be at least olm_pk_encryption_size() bytes */
OlmPkEncryption *olm_pk_encryption(
    void * memory
);

/** A null terminated string describing the most recent error to happen to an
 * encryption object */
const char * olm_pk_encryption_last_error(
    OlmPkEncryption * encryption
);

/** Clears the memory used to back this encryption object */
size_t olm_clear_pk_encryption(
    OlmPkEncryption *encryption
);

/** Set the recipient's public key for encrypting to */
size_t olm_pk_encryption_set_recipient_key(
    OlmPkEncryption *encryption,
    void const *public_key, size_t public_key_length
);

/** Get the length of the ciphertext that will correspond to a plaintext of the
 * given length. */
size_t olm_pk_ciphertext_length(
    OlmPkEncryption *encryption,
    size_t plaintext_length
);

/** Get the length of the message authentication code. */
size_t olm_pk_mac_length(
    OlmPkEncryption *encryption
);

/** Get the length of a public or ephemeral key */
size_t olm_pk_key_length(void);

/** The number of random bytes needed to encrypt a message. */
size_t olm_pk_encrypt_random_length(
    OlmPkEncryption *encryption
);

/** Encrypt a plaintext for the recipient set using
 * olm_pk_encryption_set_recipient_key. Returns olm_error() on failure. If the
 * ciphertext, mac, or ephemeral_key buffers were too small then
 * olm_pk_encryption_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". If there
 * weren't enough random bytes then olm_pk_encryption_last_error() will be
 * "NOT_ENOUGH_RANDOM". */
size_t olm_pk_encrypt(
    OlmPkEncryption *encryption,
    void const * plaintext, size_t plaintext_length,
    void * ciphertext, size_t ciphertext_length,
    void * mac, size_t mac_length,
    void * ephemeral_key, size_t ephemeral_key_size,
    void * random, size_t random_length
);

typedef struct OlmPkDecryption OlmPkDecryption;

/* The size of a decryption object in bytes */
size_t olm_pk_decryption_size(void);

/** Initialise a decryption object using the supplied memory
 *  The supplied memory must be at least olm_pk_decryption_size() bytes */
OlmPkDecryption *olm_pk_decryption(
    void * memory
);

/** A null terminated string describing the most recent error to happen to a
 * decription object */
const char * olm_pk_decryption_last_error(
    OlmPkDecryption * decryption
);

/** Clears the memory used to back this decryption object */
size_t olm_clear_pk_decryption(
    OlmPkDecryption *decryption
);

/** The number of random bytes needed to generate a new key. */
size_t olm_pk_generate_key_random_length(void);

/** Generate a new key to use for decrypting messages. The associated public
 * key will be written to the pubkey buffer. Returns olm_error() on failure. If
 * the pubkey buffer is too small then olm_pk_decryption_last_error() will be
 * "OUTPUT_BUFFER_TOO_SMALL". If there weren't enough random bytes then
 * olm_pk_decryption_last_error() will be "NOT_ENOUGH_RANDOM". */
size_t olm_pk_generate_key(
    OlmPkDecryption * decryption,
    void * pubkey, size_t pubkey_length,
    void * random, size_t random_length
);

/** Returns the number of bytes needed to store a decryption object. */
size_t olm_pickle_pk_decryption_length(
    OlmPkDecryption * decryption
);

/** Stores decryption object as a base64 string. Encrypts the object using the
 * supplied key. Returns the length of the pickled object on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_account_length() then
 * olm_pk_decryption_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_pickle_pk_decryption(
    OlmPkDecryption * decryption,
    void const * key, size_t key_length,
    void *pickled, size_t pickled_length
);

/** Loads a decryption object from a pickled base64 string. The associated
 * public key will be written to the pubkey buffer. Decrypts the object using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_pk_decryption_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_pk_decryption_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
size_t olm_unpickle_pk_decryption(
    OlmPkDecryption * decryption,
    void const * key, size_t key_length,
    void *pickled, size_t pickled_length,
    void *pubkey, size_t pubkey_length
);

/** Get the length of the plaintext that will correspond to a ciphertext of the
 * given length. */
size_t olm_pk_max_plaintext_length(
    OlmPkDecryption * decryption,
    size_t ciphertext_length
);

/** Decrypt a ciphertext.  The input ciphertext buffer is destroyed.  Returns
 * the length of the plaintext on success. Returns olm_error() on failure. If
 * the plaintext buffer is too small then olm_pk_encryption_last_error() will
 * be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_pk_decrypt(
    OlmPkDecryption * decrytion,
    void const * ephemeral_key, size_t ephemeral_key_length,
    void const * mac, size_t mac_length,
    void * ciphertext, size_t ciphertext_length,
    void * plaintext, size_t max_plaintext_length
);
