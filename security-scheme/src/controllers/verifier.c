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

#include "verifier.h"

/**
 * Gets the verifier identifier.
 *
 * @param identifier the verifier identifier
 * @return 0 if success else -1
 */
int ve_get_verifier_identifier(verifier_identifier_t *identifier)
{
    if (identifier == NULL)
    {
        return -1;
    }

    memcpy(identifier->buffer, (uint8_t[]) {
            0x16, 0x2d, 0x79, 0x36, 0xac, 0x32, 0x87, 0xbd,
            0x7e, 0x3b, 0xfa, 0x3b, 0xa0, 0xab, 0x00, 0xa9
    }, VERIFIER_MAX_ID_LENGTH);
    identifier->buffer_length = VERIFIER_MAX_ID_LENGTH;

    return 0;
}

/**
 * Generates the verifier nonce.
 *
 * @param nonce the verifier nonce
 * @return 0 if success else -1
 */
int ve_generate_nonce(verifier_nonce_t *nonce)
{
    int r;

    if (nonce == NULL)
    {
        return -1;
    }

    // random verifier nonce
    r = RAND_bytes(nonce->nonce, NONCE_LENGTH);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}

/**
 * Computes the verification of the first stage of the user show.
 *
 * @param parameters the system parameters
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_nonce the user nonce
 * @param ve_nonce the verifier nonce
 * @param ve_keys the verifier keys
 * @param ue_cipher_output the user cipher output
 * @param ve_cipher_output the verifier cipher output
 * @return 0 if success else -1
 */
int ve_verify(system_par_t *parameters, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_nonce_t ue_nonce, verifier_nonce_t ve_nonce,
              verifier_keys_t *ve_keys, user_cipher_output_t ue_cipher_output, verifier_cipher_output_t *ve_cipher_output)
{
    uint8_t k_vi_ui[AES_BLOCK_SIZE];
    uint8_t user_key[AES_BLOCK_SIZE];
    uint8_t verifier_key[AES_BLOCK_SIZE];

    user_cipher_data_t user_decipher_data;
    verifier_cipher_data_t verifier_cipher_data;

    int length;
    int r;

    if (parameters == NULL || ve_keys == NULL || ve_cipher_output == NULL)
    {
        return -1;
    }

#if defined (SECURITY_SCHEME_JAVACARD)
    memset(parameters->iv_verifier, 0, AES_IV_LENGTH);
#else
    r = RAND_bytes(parameters->iv_verifier, AES_GCM_IV_LENGTH);
    if (r != 1)
    {
        return -2;
    }
#endif

    /// compute k_vi-ui = AES (K_vi, id_u)
    length = AES_BLOCK_SIZE;
    r = aes_128_ecb_encrypt(ve_keys->private_key.sk, k_vi_ui, &length, ue_identifier.buffer, ue_identifier.buffer_length);
    if (r < 0)
    {
        return -3;
    }

    /// compute user_key = AES (k_vi-ui; "User")
    length = AES_BLOCK_SIZE;
    r = aes_128_ecb_encrypt(k_vi_ui, user_key, &length, (const unsigned char *) "000000000000User", sizeof("000000000000User") - 1);
    if (r < 0)
    {
        return -4;
    }

    /// compute verifier_key = AES (k_vi-ui; "Verifier")
    length = AES_BLOCK_SIZE;
    r = aes_128_ecb_encrypt(k_vi_ui, verifier_key, &length, (const unsigned char *) "00000000Verifier", sizeof("00000000Verifier") - 1);
    if (r < 0)
    {
        return -5;
    }

    /// compute AES (user_key; id_u, id_v, nonce_u, nonce_v)
    length = sizeof(user_cipher_output_t);
#if defined (SECURITY_SCHEME_JAVACARD)
    r = aes_128_cbc_decrypt(user_key, parameters->iv_user, &user_decipher_data, &length, ue_cipher_output.cipher_output, sizeof(user_cipher_output_t));
#else
    r = aes_128_gcm_decrypt(user_key, parameters->iv_user, &user_decipher_data, &length, ue_cipher_output.cipher_output, sizeof(user_cipher_output_t), parameters->tag);
#endif
    if (r < 0)
    {
        return -6;
    }

    /// AES (user_key; id_u, id_v, nonce_u, nonce_v) --> user_side ?= verifier_side
    // check user identifier
    r = memcmp(ue_identifier.buffer, user_decipher_data.user_identifier, USER_MAX_ID_LENGTH);
    if (r != 0)
    {
        return -7;
    }

    // check verifier identifier
    r = memcmp(ve_identifier.buffer, user_decipher_data.verifier_identifier, VERIFIER_MAX_ID_LENGTH);
    if (r != 0)
    {
        return -8;
    }

    // check user nonce
    r = memcmp(ue_nonce.nonce, user_decipher_data.user_nonce, NONCE_LENGTH);
    if (r != 0)
    {
        return -9;
    }

    // check verifier nonce
    r = memcmp(ve_nonce.nonce, user_decipher_data.verifier_nonce, NONCE_LENGTH);
    if (r != 0)
    {
        return -10;
    }

    /// random session key
    r = RAND_bytes(ve_keys->session_key.sk, AES_BLOCK_SIZE);
    if (r != 1)
    {
        return -11;
    }

    /// compute AES (verifier_key; id_v, id_u, nonce_v, nonce_u, session_key)
    memcpy(verifier_cipher_data.verifier_identifier, ve_identifier.buffer, VERIFIER_MAX_ID_LENGTH);
    memcpy(verifier_cipher_data.user_identifier, ue_identifier.buffer, USER_MAX_ID_LENGTH);
    memcpy(verifier_cipher_data.verifier_nonce, ve_nonce.nonce, NONCE_LENGTH);
    memcpy(verifier_cipher_data.user_nonce, ue_nonce.nonce, NONCE_LENGTH);
    memcpy(verifier_cipher_data.session_key, ve_keys->session_key.sk, AES_BLOCK_SIZE);

    length = sizeof(verifier_cipher_output_t);
#if defined (SECURITY_SCHEME_JAVACARD)
    r = aes_128_cbc_encrypt(verifier_key, parameters->iv_verifier, ve_cipher_output->cipher_output, &length, &verifier_cipher_data, sizeof(verifier_cipher_data_t));
#else
    r = aes_128_gcm_encrypt(verifier_key, parameters->iv_verifier, ve_cipher_output->cipher_output, &length, &verifier_cipher_data, sizeof(verifier_cipher_data_t), parameters->tag);
#endif
    if (r < 0)
    {
        return -12;
    }

    return 0;
}
