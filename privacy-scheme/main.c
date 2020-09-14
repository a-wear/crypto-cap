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

#include "controllers/issuer.h"

#if defined(PRIVACY_SCHEME_MULTOS)
# include "apdu.h"
# include "pcsc/reader.h"
# include "controllers/multos/user.h"
#elif defined(PRIVACY_SCHEME_ANDROID)
# include "apdu.h"
# include "pcsc/reader.h"
# include "controllers/android/user.h"
#else
# include "controllers/user.h"
#endif

#include "controllers/verifier.h"

#include "system.h"
#include "setup.h"

int main()
{
    struct timespec ts_start = {0, 0};
    struct timespec ts_end = {0, 0};
    double elapsed_time;

    system_par_t sys_parameters = {0};

    issuer_keys_t ie_keys = {0};
    issuer_signature_t ie_signature = {0};

    user_identifier_t ue_identifier = {0};
    user_proof_of_key_t ue_proof_of_key = {0};

    uint8_t nonce[NONCE_LENGTH] = {0};

    int r;

#if defined (PRIVACY_SCHEME_MULTOS) || defined (PRIVACY_SCHEME_ANDROID)
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwRecvLength;
    reader_t reader;
#else
    reader_t reader = NULL;
#endif

#if defined (PRIVACY_SCHEME_MULTOS) || defined (PRIVACY_SCHEME_ANDROID)
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

    // system - setup
    r = sys_setup(&sys_parameters);
    if (r < 0)
    {
        fprintf(stderr, "Error(%d): cannot initialize the system!\n", r);
        return 1;
    }

    // user - get user identifier
    r = ue_get_user_identifier(reader, &ue_identifier);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot get the user identifier!\n");
        return 1;
    }

    // issuer - setup
    r = ie_setup(&ie_keys);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot initialize the issuer!\n");
        return 1;
    }

    // issuer - user keys signature
    r = ie_issue(sys_parameters, ie_keys, ue_identifier, &ie_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot compute the user keys signature!\n");
        return 1;
    }

    // user - set issuer signature of the user's keys
    r = ue_set_user_identifier_issuer_signatures(reader, ue_identifier, ie_signature);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot set the issuer signature of the user's keys!\n");
        return 1;
    }

    // verifier - generate nonce
    r = ve_generate_nonce(nonce, sizeof(nonce));
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot generate nonce!\n");
        return 1;
    }

#ifndef NDEBUG
    fprintf(stdout, "[+] user - compute proof of key\n");
#endif

    // user - compute proof of key
    r = ue_compute_proof_of_key(reader, sys_parameters, ie_signature, nonce, sizeof(nonce), ue_identifier, &ue_proof_of_key);
    if (r < 0)
    {
        fprintf(stderr, "Error(%d): cannot compute the user proof of key!\n", r);
        return 1;
    }

#ifndef NDEBUG
    fprintf(stdout, "\n");
#endif

#ifndef NDEBUG
    fprintf(stdout, "[+] verifier - verify proof of key\n");
#endif

    // verifier - verify proof of key
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    r = ve_verify_proof_of_key(sys_parameters, ie_keys, nonce, sizeof(nonce), ue_proof_of_key);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    if (r < 0)
    {
        fprintf(stderr, "Error: cannot verify the user proof of key!\n");
        return 1;
    }

#ifndef NDEBUG
    fprintf(stdout, "\n");
#endif

    elapsed_time = ((double) ts_end.tv_sec + 1.0e-9 * (double) ts_end.tv_nsec) - ((double) ts_start.tv_sec + 1.0e-9 * (double) ts_start.tv_nsec);
    printf("[!] Elapsed time (verification) = %f\n", elapsed_time);

    fprintf(stdout, "OK!\n");

    return 0;
}
