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
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[128] = {0};
    uint8_t lc;

    int r;

    lc = 0;

    // user identifier
    memcpy(&data[lc], identifier.buffer, identifier.buffer_length);
    lc += identifier.buffer_length; // USER_MAX_ID_LENGTH

    // user private key
    memcpy(&data[lc], private_key.sk, AES_BLOCK_SIZE);
    lc += AES_BLOCK_SIZE;

    dwSendLength = sizeof(pbSendBuffer);
    r = apdu_build_command(CASE3S, CLA_APPLICATION, INS_SET_USER_IDENTIFIER_PRIVATE_KEY, 0x00, 0x00, lc, data, 0, pbSendBuffer, &dwSendLength);
    if (r < 0)
    {
        return -1;
    }

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return r;
    }

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
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t le;

    int r;

    if (identifier == NULL)
    {
        return -1;
    }

    /// exchange user information
    // expected data length to be received
    le = NONCE_LENGTH;

    dwSendLength = sizeof(pbSendBuffer);
    r = apdu_build_command(CASE2S, CLA_APPLICATION, 0x01, 0x00, 0x00, 0, NULL, le, pbSendBuffer, &dwSendLength);
    if (r < 0)
    {
        return -1;
    }

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, NULL);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return r;
    }

    // user nonce
    memcpy(nonce->nonce, pbRecvBuffer, NONCE_LENGTH);

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
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[128] = {0};
    uint8_t lc, le;

    double elapsed_time;

    int r;

    if (parameters == NULL || ue_cipher_output == NULL)
    {
        return -1;
    }

    // expected data length to be sent
    lc = 0;

    // verifier identifier
    memcpy(&data[lc], ve_identifier.buffer, ve_identifier.buffer_length);
    lc += ve_identifier.buffer_length; // VERIFIER_MAX_ID_LENGTH

    // verifier nonce
    memcpy(&data[lc], ve_nonce.nonce, NONCE_LENGTH);
    lc += NONCE_LENGTH;

    // expected data length to be received
    le = AES_GCM_IV_LENGTH + sizeof(user_cipher_output_t) + AES_GCM_TAG_LENGTH;

    dwSendLength = sizeof(pbSendBuffer);
    r = apdu_build_command(CASE4S, CLA_APPLICATION, 0x02, 0x00, 0x00, lc, data, le, pbSendBuffer, &dwSendLength);
    if (r < 0)
    {
        return -1;
    }

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, &elapsed_time);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return r;
    }

    printf("[!] Elapsed time (compute_show_stage_1) = %f\n", elapsed_time);

    // copy iv used to encrypt
    memcpy(parameters->iv_user, pbRecvBuffer, AES_GCM_IV_LENGTH);
    // copy encrypted output
    memcpy(ue_cipher_output->cipher_output, &pbRecvBuffer[AES_GCM_IV_LENGTH], sizeof(user_cipher_output_t));
    // copy tag used during encryption
    memcpy(parameters->tag, &pbRecvBuffer[AES_GCM_IV_LENGTH + sizeof(user_cipher_output_t)], AES_GCM_TAG_LENGTH);

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
    uint8_t pbSendBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwSendLength;
    uint32_t dwRecvLength;

    uint8_t data[128] = {0};
    uint8_t lc;

    double elapsed_time;

    int r;

    if (parameters == NULL)
    {
        return -1;
    }

    // expected data length to be sent
    lc = 0;

    // verifier iv
    memcpy(&data[lc], parameters->iv_verifier, AES_GCM_IV_LENGTH);
    lc += AES_GCM_IV_LENGTH;

    // verifier cipher output
    memcpy(&data[lc], ve_cipher_output.cipher_output, sizeof(verifier_cipher_output_t));
    lc += sizeof(verifier_cipher_output_t);

    // verifier tag
    memcpy(&data[lc], parameters->tag, AES_GCM_TAG_LENGTH);
    lc += AES_GCM_TAG_LENGTH;

    dwSendLength = sizeof(pbSendBuffer);
    r = apdu_build_command(CASE3S, CLA_APPLICATION, 0x03, 0x00, 0x00, lc, data, 00, pbSendBuffer, &dwSendLength);
    if (r < 0)
    {
        return -1;
    }

    dwRecvLength = sizeof(pbRecvBuffer);
    r = sc_transmit_data(reader, pbSendBuffer, dwSendLength, pbRecvBuffer, &dwRecvLength, &elapsed_time);
    if (r < 0)
    {
        fprintf(stderr, "Error: %s\n", sc_get_error(r));
        return r;
    }

    printf("[!] Elapsed time (compute_show_stage_2) = %f\n", elapsed_time);

    // 0x9001: success, 0x9002: failed
    if (pbRecvBuffer[1] != 0x01)
    {
        return -2;
    }

    return 0;
}
