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

#include <stdio.h>
#include <string.h>

#include "controllers/issuer.h"

#if defined(SECURITY_SCHEME_JAVACARD)
# include "apdu.h"
# include "pcsc/reader.h"
# include "controllers/javacard/user.h"
#elif defined(SECURITY_SCHEME_ANDROID)
# include "apdu.h"
# include "pcsc/reader.h"
# include "controllers/android/user.h"
#else
# include "controllers/user.h"
#endif

#include "controllers/verifier.h"

int main()
{
    struct timespec ts_start = {0, 0};
    struct timespec ts_end = {0, 0};
    double elapsed_time;

    system_par_t sys_parameters = {0};
    issuer_master_key_t ie_master_Key = {0};

    user_identifier_t ue_identifier = {0};
    user_keys_t ue_keys = {0};
    user_nonce_t ue_nonce = {0};
    user_cipher_output_t ue_cipher_output = {0};

    verifier_identifier_t ve_identifier = {0};
    verifier_keys_t ve_keys = {0};
    verifier_nonce_t ve_nonce = {0};
    verifier_cipher_output_t ve_cipher_output = {0};

    int r;

#if defined (SECURITY_SCHEME_JAVACARD) || defined (SECURITY_SCHEME_ANDROID)
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwRecvLength;
    reader_t reader;
#else
    reader_t reader = NULL;
#endif

#if defined (SECURITY_SCHEME_JAVACARD) || defined (SECURITY_SCHEME_ANDROID)
    r = sc_get_card_connection(&reader);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return 1;
    }

# ifndef NDEBUG
    fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION), pbRecvBuffer, &dwRecvLength, NULL);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return 1;
    }
#endif

    // issuer - setup
    r = ie_setup(&ie_master_Key);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot initialize the issuer!\n");
        return 1;
    }

    // user - get user identifier
    r = ue_get_user_identifier(reader, &ue_identifier);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot get the user identifier!\n");
        return 1;
    }

    // verifier - get user identifier
    r = ve_get_verifier_identifier(&ve_identifier);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot get the verifier identifier!\n");
        return 1;
    }

    // issuer - user and verifier secret keys generation
    r = ie_issue(&sys_parameters, ie_master_Key, ue_identifier, ve_identifier, &ue_keys.private_key, &ve_keys.private_key);
    if (r < 0)
    {
        fprintf(stderr, "Error (%d): cannot issue the user or verifier keys!\n", r);
        return 1;
    }

    // user - set user secret key
    r = ue_set_user_identifier_private_key(reader, ue_identifier, ue_keys.private_key);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot set the user identifier or private key!\n");
        return 1;
    }

    // verifier - generates the nonce
    r = ve_generate_nonce(&ve_nonce);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot generate the verifier nonce!\n");
        return 1;
    }

    // user - exchange the identifier and nonce with the verifier
    r = ue_exchange_identifier_nonce(reader, &ue_identifier, ve_identifier, &ue_nonce, ve_nonce);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot exchange the user information!\n");
        return 1;
    }

    // user - compute show stage_1
    r = ue_show_stage_1(reader, &sys_parameters, ue_identifier, ve_identifier, ue_nonce, ve_nonce, ue_keys.private_key, &ue_cipher_output);
    if (r < 0)
    {
        fprintf(stderr, "Error(%d): user show [stage_1] failed!\n", r);
        return 1;
    }

    // verifier - compute verification
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    r = ve_verify(&sys_parameters, ue_identifier, ve_identifier, ue_nonce, ve_nonce, &ve_keys, ue_cipher_output, &ve_cipher_output);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    if (r < 0)
    {
        fprintf(stderr, "Error(%d): verifier verify failed!\n", r);
        return 1;
    }

    elapsed_time = ((double) ts_end.tv_sec + 1.0e-9 * (double) ts_end.tv_nsec) - ((double) ts_start.tv_sec + 1.0e-9 * (double) ts_start.tv_nsec);
    printf("[!] Elapsed time (verification) = %f\n", elapsed_time);

    // user - compute show stage_2
    r = ue_show_stage_2(reader, &sys_parameters, ue_identifier, ve_identifier, ue_nonce, ve_nonce, &ue_keys, ve_cipher_output);
    if (r < 0)
    {
        fprintf(stderr, "Error(%d): user show [stage_2] failed!\n", r);
        return 1;
    }

    fprintf(stdout, "OK!\n");

    return 0;
}
