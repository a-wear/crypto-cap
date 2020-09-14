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

#pragma attribute("aid", "f0 00 00 02")
#pragma attribute("dir", "61 0e 4f 04 f0 00 00 02 50 06 73 65 63 73 63 68")

// ISO codes
#include <ISO7816.h>
// SmartDeck comms support
#include <multoscomms.h>
// SmartDeck crypto support
#include <multoscrypto.h>

// Standard libraries
#include <string.h>

// ECC support
#include "ecc/multosecc.h"

#include "helpers/mem_helper.h"
#include "helpers/random_helper.h"

#include "config/config.h"

#include "models/issuer.h"
#include "models/user.h"

#include "apdu.h"
#include "types.h"

/// Global values - RAM (Public memory)
#pragma melpublic
uint8_t apdu_data[APDU_L_MAX];

/// Session values - RAM (Dynamic memory)
#pragma melsession
user_proof_of_key_t user_proof_of_key = {0};

// tau and rho values
elliptic_curve_multiplier_t tau = {0x00}; // 33B
elliptic_curve_multiplier_t rho = {0x00}; // 33B
elliptic_curve_multiplier_t rho_id = {0x00}; // 33B

// key_hat_prime and t
elliptic_curve_point_t key_hat_prime = {0x04}; // 65B
elliptic_curve_point_t t = {0x04}; // 65B

elliptic_curve_multiplier_t ecm_tmp = {0x00}; // 33B
elliptic_curve_point_t ecp_tmp = {0x04}; // 65B

// user hash data
user_hash_data_t user_hash_data = {0};

/// Static values - EEPROM (Static memory)
#pragma melstatic
uint8_t elliptic_curve_base_point_affine = {0x0F};
elliptic_curve_domain_t elliptic_curve_domain = {
        0x00, // Format of domain params
        0x20, // Prime length in bytes
        0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, 0xba, 0x34, 0x4d, 0x80,
        0x00, 0x00, 0x00, 0x08, 0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
        0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, // p
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // b
        0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, 0xBA, 0x34, 0x4D, 0x80,
        0x00, 0x00, 0x00, 0x08, 0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
        0xA7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, //Gx
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //Gy
        0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, 0xba, 0x34, 0x4d, 0x80,
        0x00, 0x00, 0x00, 0x07, 0xff, 0x9f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x10,
        0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, // N
        0x01 // H
}; // mcl 256bit

user_identifier_t user_identifier = {0}; // user identifier
issuer_signature_t issuer_signature = {0}; // issuer signature (user keys)

uint8_t res = 0x00; //1B

void main(void)
{
    if (CLA != CLA_APPLICATION)
    {
        ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
    }

    switch (INS)
    {
        case INS_SET_USER_IDENTIFIER_ISSUER_SIGNATURE:
        {
            if (!CheckCase(3))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            // copy user identifier
            memcpy(&user_identifier, (const void *) apdu_data, USER_MAX_ID_LENGTH);
            // copy issuer signature
            memcpy(&issuer_signature, (const void *) &apdu_data[USER_MAX_ID_LENGTH], sizeof(issuer_signature_t));

            ExitSW(ISO7816_SW_NO_ERROR);
            break;
        }
        case INS_COMPUTE_PROOF_OF_KEY:
        {
            if (!CheckCase(4))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            /// tau and rho random numbers
            // tau
            set_by_csprng((uint8_t *) &tau.ecm);

            // rho
            set_by_csprng((uint8_t *) &rho.ecm);

            // rho_id
            set_by_csprng((uint8_t *) &rho_id.ecm);

            /// signatures
            // key_hat
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_proof_of_key.key_hat, (uint8_t *) &issuer_signature.user_key, (uint8_t *) &tau);

            // key_hat_prime
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &key_hat_prime, (uint8_t *) &issuer_signature.user_key_prime, (uint8_t *) &tau);

            /// t values
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &t, (uint8_t *) &elliptic_curve_base_point_affine, (uint8_t *) &rho);
            t.form = 0x04;
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_tmp, (uint8_t *) &key_hat_prime, (uint8_t *) &rho_id);
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &t, (uint8_t *) &t, (uint8_t *) &ecp_tmp);

            /// e <-- H(...)
            __multos_memcpy_non_atomic_fixed_length((void *) &user_hash_data.key_hat, (void *) &user_proof_of_key.key_hat, sizeof(elliptic_curve_point_t)); // key_hat
            __multos_memcpy_non_atomic_fixed_length((void *) &user_hash_data.t, (void *) &t, sizeof(elliptic_curve_point_t)); // t
            __multos_memcpy_non_atomic_fixed_length((void *) &user_hash_data.nonce, apdu_data, NONCE_LENGTH); // nonce
            SHA1(sizeof(user_hash_data_t), (uint8_t *) &user_proof_of_key.e, (uint8_t *) &user_hash_data);

            /// s values
            // s
            __multos_memzero((uint8_t *) &ecm_tmp.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_proof_of_key.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp.ecm, (uint8_t *) &tau.ecm, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __modular_addition((uint8_t *) &user_proof_of_key.s, (uint8_t *) &rho.ecm, (uint8_t *) &ecm_tmp.ecm, EC_SIZE);
            __modular_reduction((uint8_t *) &user_proof_of_key.s, EC_SIZE + 1, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);

            // s_id
            __multos_memzero((uint8_t *) &ecm_tmp.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_proof_of_key.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp.ecm, (uint8_t *) &user_identifier.buffer, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __multos_memcmp_fixed_length((uint8_t *) &ecm_tmp.ecm, (uint8_t *) &rho_id.ecm, EC_SIZE, (uint8_t *) &res);
            if (res == 0x08)
            {
                __subtraction((uint8_t *) &user_proof_of_key.s_id, (uint8_t *) &rho_id.ecm, (uint8_t *) &ecm_tmp.ecm, EC_SIZE);
            }
            else
            {
                __modular_subtraction((uint8_t *) &user_proof_of_key.s_id, (uint8_t *) &rho_id.ecm, (uint8_t *) &ecm_tmp.ecm, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N);
            }

            /// copy proof of key
            __multos_memcpy_non_atomic_fixed_length(apdu_data, (void *) &user_proof_of_key, sizeof(user_proof_of_key_t));

            ExitSWLa(ISO7816_SW_NO_ERROR, sizeof(user_proof_of_key_t));
            break;
        }
        default:
        {
            ExitSW(ISO7816_SW_INS_NOT_SUPPORTED);
            break;
        }
    }
}

/**
 * Writes random bytes to address by cryptographically secure
 * pseudo random number generator.
 *
 * @param address pointer to where the random number will be written
 */
void set_by_csprng(unsigned char *address)
{
    __set_by_csprng(address);
    __modular_reduction(address, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
}
