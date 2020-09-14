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
 * Generates the issuer keys.
 *
 * @param keys the issuer keys
 * @return 0 if success else -1
 */
int ie_setup(issuer_keys_t *keys)
{
    int r;

    if (keys == NULL)
    {
        return -1;
    }

    // issuer private key - K(0)
    mclBnFr_setByCSPRNG(&keys->issuer_key_0.sk);
    r = mclBnFr_isValid(&keys->issuer_key_0.sk);
    if (r != 1)
    {
        return -2;
    }

    // issuer private key - K(1)
    mclBnFr_setByCSPRNG(&keys->issuer_key_1.sk);
    r = mclBnFr_isValid(&keys->issuer_key_1.sk);
    if (r != 1)
    {
        return -3;
    }

    // issuer private key - K(2)
    mclBnFr_setByCSPRNG(&keys->issuer_key_2.sk);
    r = mclBnFr_isValid(&keys->issuer_key_2.sk);
    if (r != 1)
    {
        return -4;
    }

    return 0;
}

/**
 * Computes the signature of the user key and key prime using the private keys.
 *
 * @param sys_parameters the system parameters
 * @param keys the issuer keys
 * @param ue_identifier the user identifier
 * @param signature the signature of the user keys
 * @return 0 if success else -1
 */
int ie_issue(system_par_t sys_parameters, issuer_keys_t keys, user_identifier_t ue_identifier, issuer_signature_t *signature)
{
    mclBnFr number_one, identifier, epoch;
    mclBnFr add_result, mul_result, div_result;

    unsigned char value[EC_SIZE] = {0};

    int r;

    if (signature == NULL)
    {
        return -1;
    }

    // set 1 to Fr data type
    mclBnFr_setInt32(&number_one, 1);

    // set identifier to Fr mcl type
    mcl_bytes_to_Fr(&identifier, ue_identifier.buffer, EC_SIZE); // convert to mcl type

    // set epoch to Fr mcl type
    memset(value, 0, EC_SIZE); // zero memory
    generate_epoch(&value[EPOCH_OFFSET], EPOCH_LENGTH); // generate epoch
    mcl_bytes_to_Fr(&epoch, value, EC_SIZE); // convert to mcl type

    /// user_key
    memcpy(&add_result, &keys.issuer_key_0.sk, sizeof(mclBnFr)); // add_result = K(0)
    mclBnFr_mul(&mul_result, &keys.issuer_key_1.sk, &identifier); // mul_result = K(1)·ID
    mclBnFr_add(&add_result, &add_result, &mul_result); // add_result = add_result + mul_result
    mclBnFr_mul(&mul_result, &keys.issuer_key_2.sk, &epoch); // mul_result = K(2)·E
    mclBnFr_add(&add_result, &add_result, &mul_result); // add_result = add_result + mul_result

    mclBnFr_div(&div_result, &number_one, &add_result); // div_result = 1 / add_result
    mclBnG1_mul(&signature->user_key, &sys_parameters.G1, &div_result); // user_key = G1 * div_result
    mclBnG1_normalize(&signature->user_key, &signature->user_key);
    r = mclBnG1_isValid(&signature->user_key);
    if (r != 1)
    {
        return -2;
    }

    /// user_key prime
    mclBnG1_mul(&signature->user_key_prime, &signature->user_key, &keys.issuer_key_1.sk); // user_key_prime = user_key·K(1)
    mclBnG1_normalize(&signature->user_key_prime, &signature->user_key_prime);
    r = mclBnG1_isValid(&signature->user_key_prime);
    if (r != 1)
    {
        return -3;
    }

    return 0;
}