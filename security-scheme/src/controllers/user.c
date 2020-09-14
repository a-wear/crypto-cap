/**
 *
 *  Copyright (C) 2020  Raul Casanova Marques
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "user.h"

/**
 * Gets the user identifier.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier
 * @return 0 if success else -1
 */
int ue_get_user_identifier(reader_t reader, user_identifier_t *identifier)
{
    if (identifier == NULL)
    {
        return -1;
    }

    memcpy(identifier->buffer, (uint8_t[]) {
            0x04, 0x82, 0x13, 0x09, 0x2a, 0x09, 0x27, 0xc6,
            0xbb, 0xd6, 0x7c, 0xb2, 0x2c, 0x43, 0x06, 0x2e
    }, USER_MAX_ID_LENGTH);
    identifier->buffer_length = USER_MAX_ID_LENGTH;

    return 0;
}

/**
 * Sets the user identifier and private key using the specified reader.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier
 * @param private_key the user private key
 * @return 0 if success else -1
 */
int ue_set_user_identifier_private_key(reader_t reader, user_identifier_t identifier, user_private_key_t private_key)
{
    return 0;
}

/**
 * Exchanges the identifier and the nonce between the user and the verifier using the specified reader.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier to be received
 * @param ve_identifier the verifier identifier to be sent
 * @param nonce the user nonce to be received
 * @param ve_nonce the verifier nonce to be sent
 * @return 0 if success else -1
 */
int ue_exchange_identifier_nonce(reader_t reader, user_identifier_t *identifier, verifier_identifier_t ve_identifier, user_nonce_t *nonce, verifier_nonce_t ve_nonce)
{
    int r;

    if (identifier == NULL || nonce == NULL)
    {
        return -1;
    }

    // random user nonce
    r = RAND_bytes(nonce->nonce, NONCE_LENGTH);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}

/**
 * Computes the first stage of the user show using the specified reader.
 *
 * @param reader the reader to be used
 * @param parameters the system parameters
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_nonce the user nonce
 * @param ve_nonce the verifier nonce
 * @param ue_private_key the user private key
 * @param ue_cipher_output the user cipher output
 * @return 0 if success else -1
 */
int ue_show_stage_1(reader_t reader, system_par_t *parameters, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_nonce_t ue_nonce, verifier_nonce_t ve_nonce,
                    user_private_key_t ue_private_key, user_cipher_output_t *ue_cipher_output)
{
    uint8_t user_key[AES_BLOCK_SIZE];

    user_cipher_data_t user_cipher_data;

    int length;
    int r;

    if (parameters == NULL || ue_cipher_output == NULL)
    {
        return -1;
    }

    // random iv - user key
    r = RAND_bytes(parameters->iv_user, AES_GCM_IV_LENGTH);
    if (r != 1)
    {
        return -2;
    }

    /// compute user_key = AES (k_vi-ui; "User")
    length = AES_BLOCK_SIZE;
    r = aes_128_ecb_encrypt(ue_private_key.sk, user_key, &length, (const unsigned char *) "000000000000User", sizeof("000000000000User") - 1);
    if (r < 0)
    {
        return -3;
    }

    /// compute AES (user_key; id_u, id_v, nonce_u, nonce_v)
    memcpy(user_cipher_data.user_identifier, ue_identifier.buffer, USER_MAX_ID_LENGTH);
    memcpy(user_cipher_data.verifier_identifier, ve_identifier.buffer, VERIFIER_MAX_ID_LENGTH);
    memcpy(user_cipher_data.user_nonce, ue_nonce.nonce, NONCE_LENGTH);
    memcpy(user_cipher_data.verifier_nonce, ve_nonce.nonce, NONCE_LENGTH);

    length = sizeof(user_cipher_output_t);
    r = aes_128_gcm_encrypt(user_key, parameters->iv_user, ue_cipher_output->cipher_output, &length, &user_cipher_data, sizeof(user_cipher_data_t), parameters->tag);
    if (r < 0)
    {
        return -4;
    }

    return 0;
}

/**
 * Computes the second stage of the user show and gets the session key using the specified reader.
 *
 * @param reader the reader to be used
 * @param parameters the system parameters
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_nonce the user nonce
 * @param ve_nonce the verifier nonce
 * @param ue_keys the user keys
 * @param ve_cipher_output the verifier cipher output
 * @return 0 if success else -1
 */
int ue_show_stage_2(reader_t reader, system_par_t *parameters, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_nonce_t ue_nonce, verifier_nonce_t ve_nonce,
                    user_keys_t *ue_keys, verifier_cipher_output_t ve_cipher_output)
{
    uint8_t verifier_key[AES_BLOCK_SIZE];

    verifier_cipher_data_t verifier_decipher_data;

    int length;
    int r;

    if (parameters == NULL)
    {
        return -1;
    }

    /// compute verifier_key = AES (k_vi-ui; "Verifier")
    length = AES_BLOCK_SIZE;
    r = aes_128_ecb_encrypt(ue_keys->private_key.sk, verifier_key, &length, (const unsigned char *) "00000000Verifier", sizeof("00000000Verifier") - 1);
    if (r < 0)
    {
        return -2;
    }

    /// compute AES (verifier_key; id_v, id_u, nonce_v, nonce_u, session_key)
    length = sizeof(verifier_cipher_output_t);
    r = aes_128_gcm_decrypt(verifier_key, parameters->iv_verifier, &verifier_decipher_data, &length, ve_cipher_output.cipher_output, sizeof(verifier_cipher_output_t), parameters->tag);
    if (r < 0)
    {
        return -3;
    }

    /// AES (verifier_key; id_v, id_u, nonce_v, nonce_u, session_key) --> verifier_side ?= user_side
    // check verifier identifier
    r = memcmp(ve_identifier.buffer, verifier_decipher_data.verifier_identifier, VERIFIER_MAX_ID_LENGTH);
    if (r != 0)
    {
        return -4;
    }

    // check user identifier
    r = memcmp(ue_identifier.buffer, verifier_decipher_data.user_identifier, USER_MAX_ID_LENGTH);
    if (r != 0)
    {
        return -5;
    }

    // check verifier nonce
    r = memcmp(ve_nonce.nonce, verifier_decipher_data.verifier_nonce, NONCE_LENGTH);
    if (r != 0)
    {
        return -6;
    }

    // check user nonce
    r = memcmp(ue_nonce.nonce, verifier_decipher_data.user_nonce, NONCE_LENGTH);
    if (r != 0)
    {
        return -7;
    }

    // get session key
    memcpy(ue_keys->session_key.sk, verifier_decipher_data.session_key, AES_BLOCK_SIZE);

    return 0;
}
