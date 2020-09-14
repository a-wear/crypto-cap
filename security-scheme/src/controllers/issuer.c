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

#include "issuer.h"

/**
 * Generates the issuer master key.
 *
 * @param master_key the issuer master key
 * @return 0 if success else -1
 */
int ie_setup(issuer_master_key_t *master_key)
{
    int r;

    if (master_key == NULL)
    {
        return -1;
    }

    // random master key
    r = RAND_bytes(master_key->sk, NONCE_LENGTH);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}

/**
 * Generates a unique secret key for the user and the verifier.
 *
 * @param parameters the system parameters
 * @param master_key the issuer master key
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_private_key the user private key
 * @param ve_private_key the verifier private key
 * @return 0 if success else -1
 */
int ie_issue(system_par_t *parameters, issuer_master_key_t master_key, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_private_key_t *ue_private_key, verifier_private_key_t *ve_private_key)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    if (parameters == NULL || ue_private_key == NULL || ve_private_key == NULL)
    {
        return -1;
    }

    // Create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -2;
    }

    /// verifier key derivation
    // initialise the encryption operation using the issuer master key
    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, master_key.sk, NULL);
    if (r != 1)
    {
        return -4;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the verifier private key using its identifier
    r = EVP_EncryptUpdate(ctx, ve_private_key->sk, &length, ve_identifier.buffer, ve_identifier.buffer_length);
    if (r != 1)
    {
        return -5;
    }
    assert(length == AES_BLOCK_SIZE); // no padding, data length is 128 bits

    // finalise the encryption
    r = EVP_EncryptFinal_ex(ctx, ve_private_key->sk, &length);
    if (r != 1)
    {
        return -6;
    }
    assert(length == 0); // no output expected, length must be 0

    /// user key derivation
    // initialise the encryption operation using the verifier secret key
    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, ve_private_key->sk, NULL);
    if (r != 1)
    {
        return -7;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the user private key using its identifier
    r = EVP_EncryptUpdate(ctx, ue_private_key->sk, &length, ue_identifier.buffer, ue_identifier.buffer_length);
    if (r != 1)
    {
        return -8;
    }
    assert(length == AES_BLOCK_SIZE); // no padding, data length is 128 bits

    // finalise the encryption
    r = EVP_EncryptFinal_ex(ctx, ue_private_key->sk, &length);
    if (r != 1)
    {
        return -9;
    }
    assert(length == 0); // no output expected, length must be 0

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
