/* Copyright 2015, 2016 OpenMarket Ltd
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

static const size_t OLM_MESSAGE_TYPE_PRE_KEY = 0;
static const size_t OLM_MESSAGE_TYPE_MESSAGE = 1;

typedef struct OlmAccount OlmAccount;
typedef struct OlmSession OlmSession;
typedef struct OlmUtility OlmUtility;

/** Get the version number of the library.
 * Arguments will be updated if non-null.
 */
void olm_get_library_version(uint8_t *major, uint8_t *minor, uint8_t *patch);

/** The size of an account object in bytes */
size_t olm_account_size();

/** The size of a session object in bytes */
size_t olm_session_size();

/** The size of a utility object in bytes */
size_t olm_utility_size();

/** Initialise an account object using the supplied memory
 *  The supplied memory must be at least olm_account_size() bytes */
OlmAccount * olm_account(
    void * memory
);

/** Initialise a session object using the supplied memory
 *  The supplied memory must be at least olm_session_size() bytes */
OlmSession * olm_session(
    void * memory
);

/** Initialise a utility object using the supplied memory
 *  The supplied memory must be at least olm_utility_size() bytes */
OlmUtility * olm_utility(
    void * memory
);

/** The value that olm will return from a function if there was an error */
size_t olm_error();

/** A null terminated string describing the most recent error to happen to an
 * account */
const char * olm_account_last_error(
    OlmAccount * account
);

/** A null terminated string describing the most recent error to happen to a
 * session */
const char * olm_session_last_error(
    OlmSession * session
);

/** A null terminated string describing the most recent error to happen to a
 * utility */
const char * olm_utility_last_error(
    OlmUtility * utility
);

/** Clears the memory used to back this account */
size_t olm_clear_account(
    OlmAccount * account
);

/** Clears the memory used to back this session */
size_t olm_clear_session(
    OlmSession * session
);

/** Clears the memory used to back this utility */
size_t olm_clear_utility(
    OlmUtility * utility
);

/** Returns the number of bytes needed to store an account */
size_t olm_pickle_account_length(
    OlmAccount * account
);

/** Returns the number of bytes needed to store a session */
size_t olm_pickle_session_length(
    OlmSession * session
);

/** Stores an account as a base64 string. Encrypts the account using the
 * supplied key. Returns the length of the pickled account on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_account_length() then
 * olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_pickle_account(
    OlmAccount * account,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** Stores a session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the pickled session on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_session_length() then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_pickle_session(
    OlmSession * session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** Loads an account from a pickled base64 string. Decrypts the account using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_account_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_account_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
size_t olm_unpickle_account(
    OlmAccount * account,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** Loads a session from a pickled base64 string. Decrypts the session using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_session_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_session_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
size_t olm_unpickle_session(
    OlmSession * session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** The number of random bytes needed to create an account.*/
size_t olm_create_account_random_length(
    OlmAccount * account
);

/** Creates a new account. Returns olm_error() on failure. If weren't
 * enough random bytes then olm_account_last_error() will be
 * "NOT_ENOUGH_RANDOM" */
size_t olm_create_account(
    OlmAccount * account,
    void * random, size_t random_length
);

/** The size of the output buffer needed to hold the identity keys */
size_t olm_account_identity_keys_length(
    OlmAccount * account
);

/** Writes the public parts of the identity keys for the account into the
 * identity_keys output buffer. Returns olm_error() on failure. If the
 * identity_keys buffer was too small then olm_account_last_error() will be
 * "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_account_identity_keys(
    OlmAccount * account,
    void * identity_keys, size_t identity_key_length
);


/** The length of an ed25519 signature encoded as base64. */
size_t olm_account_signature_length(
    OlmAccount * account
);

/** Signs a message with the ed25519 key for this account. Returns olm_error()
 * on failure. If the signature buffer was too small then
 * olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_account_sign(
    OlmAccount * account,
    void const * message, size_t message_length,
    void * signature, size_t signature_length
);

/** The size of the output buffer needed to hold the one time keys */
size_t olm_account_one_time_keys_length(
    OlmAccount * account
);

/** Writes the public parts of the unpublished one time keys for the account
 * into the one_time_keys output buffer.
 * <p>
 * The returned data is a JSON-formatted object with the single property
 * <tt>curve25519</tt>, which is itself an object mapping key id to
 * base64-encoded Curve25519 key. For example:
 * <pre>
 * {
 *     curve25519: {
 *         "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
 *         "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
 *     }
 * }
 * </pre>
 * Returns olm_error() on failure.
 * <p>
 * If the one_time_keys buffer was too small then olm_account_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_account_one_time_keys(
    OlmAccount * account,
    void * one_time_keys, size_t one_time_keys_length
);

/** Marks the current set of one time keys as being published. */
size_t olm_account_mark_keys_as_published(
    OlmAccount * account
);

/** The largest number of one time keys this account can store. */
size_t olm_account_max_number_of_one_time_keys(
    OlmAccount * account
);

/** The number of random bytes needed to generate a given number of new one
 * time keys. */
size_t olm_account_generate_one_time_keys_random_length(
    OlmAccount * account,
    size_t number_of_keys
);

/** Generates a number of new one time keys. If the total number of keys stored
 * by this account exceeds max_number_of_one_time_keys() then the old keys are
 * discarded. Returns olm_error() on error. If the number of random bytes is
 * too small then olm_account_last_error() will be "NOT_ENOUGH_RANDOM". */
size_t olm_account_generate_one_time_keys(
    OlmAccount * account,
    size_t number_of_keys,
    void * random, size_t random_length
);

/** The number of random bytes needed to create an outbound session */
size_t olm_create_outbound_session_random_length(
    OlmSession * session
);

/** Creates a new out-bound session for sending messages to a given identity_key
 * and one_time_key. Returns olm_error() on failure. If the keys couldn't be
 * decoded as base64 then olm_session_last_error() will be "INVALID_BASE64"
 * If there weren't enough random bytes then olm_session_last_error() will
 * be "NOT_ENOUGH_RANDOM". */
size_t olm_create_outbound_session(
    OlmSession * session,
    OlmAccount * account,
    void const * their_identity_key, size_t their_identity_key_length,
    void const * their_one_time_key, size_t their_one_time_key_length,
    void * random, size_t random_length
);

/** Create a new in-bound session for sending/receiving messages from an
 * incoming PRE_KEY message. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
 * key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID". */
size_t olm_create_inbound_session(
    OlmSession * session,
    OlmAccount * account,
    void * one_time_key_message, size_t message_length
);

/** Create a new in-bound session for sending/receiving messages from an
 * incoming PRE_KEY message. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
 * key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID". */
size_t olm_create_inbound_session_from(
    OlmSession * session,
    OlmAccount * account,
    void const * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
);

/** The length of the buffer needed to return the id for this session. */
size_t olm_session_id_length(
    OlmSession * session
);

/** An identifier for this session. Will be the same for both ends of the
 * conversation. If the id buffer is too small then olm_session_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_session_id(
    OlmSession * session,
    void * id, size_t id_length
);

int olm_session_has_received_message(
    OlmSession *session
);

/** Checks if the PRE_KEY message is for this in-bound session. This can happen
 * if multiple messages are sent to this account before this account sends a
 * message in reply. Returns 1 if the session matches. Returns 0 if the session
 * does not match. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
size_t olm_matches_inbound_session(
    OlmSession * session,
    void * one_time_key_message, size_t message_length
);

/** Checks if the PRE_KEY message is for this in-bound session. This can happen
 * if multiple messages are sent to this account before this account sends a
 * message in reply. Returns 1 if the session matches. Returns 0 if the session
 * does not match. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
size_t olm_matches_inbound_session_from(
    OlmSession * session,
    void const * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
);

/** Removes the one time keys that the session used from the account. Returns
 * olm_error() on failure. If the account doesn't have any matching one time
 * keys then olm_account_last_error() will be "BAD_MESSAGE_KEY_ID". */
size_t olm_remove_one_time_keys(
    OlmAccount * account,
    OlmSession * session
);

/** The type of the next message that olm_encrypt() will return. Returns
 * OLM_MESSAGE_TYPE_PRE_KEY if the message will be a PRE_KEY message.
 * Returns OLM_MESSAGE_TYPE_MESSAGE if the message will be a normal message.
 * Returns olm_error on failure. */
size_t olm_encrypt_message_type(
    OlmSession * session
);

/** The number of random bytes needed to encrypt the next message. */
size_t olm_encrypt_random_length(
    OlmSession * session
);

/** The size of the next message in bytes for the given number of plain-text
 * bytes. */
size_t olm_encrypt_message_length(
    OlmSession * session,
    size_t plaintext_length
);

/** Encrypts a message using the session. Returns the length of the message in
 * bytes on success. Writes the message as base64 into the message buffer.
 * Returns olm_error() on failure. If the message buffer is too small then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". If there
 * weren't enough random bytes then olm_session_last_error() will be
 * "NOT_ENOUGH_RANDOM". */
size_t olm_encrypt(
    OlmSession * session,
    void const * plaintext, size_t plaintext_length,
    void * random, size_t random_length,
    void * message, size_t message_length
);

/** The maximum number of bytes of plain-text a given message could decode to.
 * The actual size could be different due to padding. The input message buffer
 * is destroyed. Returns olm_error() on failure. If the message base64
 * couldn't be decoded then olm_session_last_error() will be
 * "INVALID_BASE64". If the message is for an unsupported version of the
 * protocol then olm_session_last_error() will be "BAD_MESSAGE_VERSION".
 * If the message couldn't be decoded then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
size_t olm_decrypt_max_plaintext_length(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length
);

/** Decrypts a message using the session. The input message buffer is destroyed.
 * Returns the length of the plain-text on success. Returns olm_error() on
 * failure. If the plain-text buffer is smaller than
 * olm_decrypt_max_plaintext_length() then olm_session_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". If the base64 couldn't be decoded then
 * olm_session_last_error() will be "INVALID_BASE64". If the message is for
 * an unsupported version of the protocol then olm_session_last_error() will
 *  be "BAD_MESSAGE_VERSION". If the message couldn't be decoded then
 *  olm_session_last_error() will be BAD_MESSAGE_FORMAT".
 *  If the MAC on the message was invalid then olm_session_last_error() will
 *  be "BAD_MESSAGE_MAC". */
size_t olm_decrypt(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length,
    void * plaintext, size_t max_plaintext_length
);

/** The length of the buffer needed to hold the SHA-256 hash. */
size_t olm_sha256_length(
   OlmUtility * utility
);

/** Calculates the SHA-256 hash of the input and encodes it as base64. If the
 * output buffer is smaller than olm_sha256_length() then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_sha256(
    OlmUtility * utility,
    void const * input, size_t input_length,
    void * output, size_t output_length
);

/** Verify an ed25519 signature. If the key was too small then
 * olm_session_last_error will be "INVALID_BASE64". If the signature was invalid
 * then olm_session_last_error() will be "BAD_MESSAGE_MAC". */
size_t olm_ed25519_verify(
    OlmUtility * utility,
    void const * key, size_t key_length,
    void const * message, size_t message_length,
    void * signature, size_t signature_length
);

typedef struct OlmOutboundGroupSession OlmOutboundGroupSession;

/** get the size of an outbound group session, in bytes. */
size_t olm_outbound_group_session_size();

/**
 * Initialise an outbound group session object using the supplied memory
 * The supplied memory should be at least olm_outbound_group_session_size()
 * bytes.
 */
OlmOutboundGroupSession * olm_outbound_group_session(
    void *memory
);

/**
 * A null terminated string describing the most recent error to happen to a
 * group session */
const char *olm_outbound_group_session_last_error(
    const OlmOutboundGroupSession *session
);

/** Clears the memory used to back this group session */
size_t olm_clear_outbound_group_session(
    OlmOutboundGroupSession *session
);

/** Returns the number of bytes needed to store an outbound group session */
size_t olm_pickle_outbound_group_session_length(
    const OlmOutboundGroupSession *session
);

/**
 * Stores a group session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the session on success.
 *
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_outbound_group_session_length() then
 * olm_outbound_group_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
 */
size_t olm_pickle_outbound_group_session(
    OlmOutboundGroupSession *session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/**
 * Loads a group session from a pickled base64 string. Decrypts the session
 * using the supplied key.
 *
 * Returns olm_error() on failure. If the key doesn't match the one used to
 * encrypt the account then olm_outbound_group_session_last_error() will be
 * "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_outbound_group_session_last_error() will be "INVALID_BASE64". The input
 * pickled buffer is destroyed
 */
size_t olm_unpickle_outbound_group_session(
    OlmOutboundGroupSession *session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);


/** The number of random bytes needed to create an outbound group session */
size_t olm_init_outbound_group_session_random_length(
    const OlmOutboundGroupSession *session
);

/**
 * Start a new outbound group session. Returns olm_error() on failure. On
 * failure last_error will be set with an error code. The last_error will be
 * NOT_ENOUGH_RANDOM if the number of random bytes was too small.
 */
size_t olm_init_outbound_group_session(
    OlmOutboundGroupSession *session,
    uint8_t *random, size_t random_length
);

/**
 * The number of bytes that will be created by encrypting a message
 */
size_t olm_group_encrypt_message_length(
    OlmOutboundGroupSession *session,
    size_t plaintext_length
);

/**
 * Encrypt some plain-text. Returns the length of the encrypted message or
 * olm_error() on failure. On failure last_error will be set with an
 * error code. The last_error will be OUTPUT_BUFFER_TOO_SMALL if the output
 * buffer is too small.
 */
size_t olm_group_encrypt(
    OlmOutboundGroupSession *session,
    uint8_t const * plaintext, size_t plaintext_length,
    uint8_t * message, size_t message_length
);


/**
 * Get the number of bytes returned by olm_outbound_group_session_id()
 */
size_t olm_outbound_group_session_id_length(
    const OlmOutboundGroupSession *session
);

/**
 * Get a base64-encoded identifier for this session.
 *
 * Returns the length of the session id on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be OUTPUT_BUFFER_TOO_SMALL if the id buffer was too
 * small.
 */
size_t olm_outbound_group_session_id(
    OlmOutboundGroupSession *session,
    uint8_t * id, size_t id_length
);

/**
 * Get the current message index for this session.
 *
 * Each message is sent with an increasing index; this returns the index for
 * the next message.
 */
uint32_t olm_outbound_group_session_message_index(
    OlmOutboundGroupSession *session
);

/**
 * Get the number of bytes returned by olm_outbound_group_session_key()
 */
size_t olm_outbound_group_session_key_length(
    const OlmOutboundGroupSession *session
);

/**
 * Get the base64-encoded current ratchet key for this session.
 *
 * Each message is sent with a different ratchet key. This function returns the
 * ratchet key that will be used for the next message.
 *
 * Returns the length of the ratchet key on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be OUTPUT_BUFFER_TOO_SMALL if the buffer was too small.
 */
size_t olm_outbound_group_session_key(
    OlmOutboundGroupSession *session,
    uint8_t * key, size_t key_length
);

typedef struct OlmInboundGroupSession OlmInboundGroupSession;

/** get the size of an inbound group session, in bytes. */
size_t olm_inbound_group_session_size();

/**
 * Initialise an inbound group session object using the supplied memory
 * The supplied memory should be at least olm_inbound_group_session_size()
 * bytes.
 */
OlmInboundGroupSession * olm_inbound_group_session(
    void *memory
);

/**
 * A null terminated string describing the most recent error to happen to a
 * group session */
const char *olm_inbound_group_session_last_error(
    const OlmInboundGroupSession *session
);

/** Clears the memory used to back this group session */
size_t olm_clear_inbound_group_session(
    OlmInboundGroupSession *session
);

/** Returns the number of bytes needed to store an inbound group session */
size_t olm_pickle_inbound_group_session_length(
    const OlmInboundGroupSession *session
);

/**
 * Stores a group session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the session on success.
 *
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_inbound_group_session_length() then
 * olm_inbound_group_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
 */
size_t olm_pickle_inbound_group_session(
    OlmInboundGroupSession *session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/**
 * Loads a group session from a pickled base64 string. Decrypts the session
 * using the supplied key.
 *
 * Returns olm_error() on failure. If the key doesn't match the one used to
 * encrypt the account then olm_inbound_group_session_last_error() will be
 * "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_inbound_group_session_last_error() will be "INVALID_BASE64". The input
 * pickled buffer is destroyed
 */
size_t olm_unpickle_inbound_group_session(
    OlmInboundGroupSession *session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);


/**
 * Start a new inbound group session, from a key exported from
 * olm_outbound_group_session_key
 *
 * Returns olm_error() on failure. On failure last_error will be set with an
 * error code. The last_error will be:
 *
 *  * OLM_INVALID_BASE64  if the session_key is not valid base64
 *  * OLM_BAD_SESSION_KEY if the session_key is invalid
 */
size_t olm_init_inbound_group_session(
    OlmInboundGroupSession *session,
    /* base64-encoded keys */
    uint8_t const * session_key, size_t session_key_length
);

/**
 * Import an inbound group session, from a previous export.
 *
 * Returns olm_error() on failure. On failure last_error will be set with an
 * error code. The last_error will be:
 *
 *  * OLM_INVALID_BASE64  if the session_key is not valid base64
 *  * OLM_BAD_SESSION_KEY if the session_key is invalid
 */
size_t olm_import_inbound_group_session(
    OlmInboundGroupSession *session,
    /* base64-encoded keys; note that it will be overwritten with the base64-decoded
       data. */
    uint8_t const * session_key, size_t session_key_length
);


/**
 * Get an upper bound on the number of bytes of plain-text the decrypt method
 * will write for a given input message length. The actual size could be
 * different due to padding.
 *
 * The input message buffer is destroyed.
 *
 * Returns olm_error() on failure.
 */
size_t olm_group_decrypt_max_plaintext_length(
    OlmInboundGroupSession *session,
    uint8_t * message, size_t message_length
);

/**
 * Decrypt a message.
 *
 * The input message buffer is destroyed.
 *
 * Returns the length of the decrypted plain-text, or olm_error() on failure.
 *
 * On failure last_error will be set with an error code. The last_error will
 * be:
 *   * OLM_OUTPUT_BUFFER_TOO_SMALL if the plain-text buffer is too small
 *   * OLM_INVALID_BASE64 if the message is not valid base-64
 *   * OLM_BAD_MESSAGE_VERSION if the message was encrypted with an unsupported
 *     version of the protocol
 *   * OLM_BAD_MESSAGE_FORMAT if the message headers could not be decoded
 *   * OLM_BAD_MESSAGE_MAC    if the message could not be verified
 *   * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key corresponding to the
 *     message's index (ie, it was sent before the session key was shared with
 *     us)
 */
size_t olm_group_decrypt(
    OlmInboundGroupSession *session,

    /* input; note that it will be overwritten with the base64-decoded
       message. */
    uint8_t * message, size_t message_length,

    /* output */
    uint8_t * plaintext, size_t max_plaintext_length,
    uint32_t * message_index
);


/**
 * Get the number of bytes returned by olm_inbound_group_session_id()
 */
size_t olm_inbound_group_session_id_length(
    const OlmInboundGroupSession *session
);

/**
 * Get a base64-encoded identifier for this session.
 *
 * Returns the length of the session id on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be OUTPUT_BUFFER_TOO_SMALL if the id buffer was too
 * small.
 */
size_t olm_inbound_group_session_id(
    OlmInboundGroupSession *session,
    uint8_t * id, size_t id_length
);

/**
 * Get the first message index we know how to decrypt.
 */
uint32_t olm_inbound_group_session_first_known_index(
    const OlmInboundGroupSession *session
);


/**
 * Check if the session has been verified as a valid session.
 *
 * (A session is verified either because the original session share was signed,
 * or because we have subsequently successfully decrypted a message.)
 *
 * This is mainly intended for the unit tests, currently.
 */
int olm_inbound_group_session_is_verified(
    const OlmInboundGroupSession *session
);

/**
 * Get the number of bytes returned by olm_export_inbound_group_session()
 */
size_t olm_export_inbound_group_session_length(
    const OlmInboundGroupSession *session
);

/**
 * Export the base64-encoded ratchet key for this session, at the given index,
 * in a format which can be used by olm_import_inbound_group_session
 *
 * Returns the length of the ratchet key on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be:
 *   * OUTPUT_BUFFER_TOO_SMALL if the buffer was too small
 *   * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key corresponding to the
 *     given index (ie, it was sent before the session key was shared with
 *     us)
 */
size_t olm_export_inbound_group_session(
    OlmInboundGroupSession *session,
    uint8_t * key, size_t key_length, uint32_t message_index
);
