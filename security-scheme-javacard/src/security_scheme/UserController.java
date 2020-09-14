/*
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

package security_scheme;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class UserController {

    /**
     * User model
     */
    private final UserModel model;

    /**
     * Buffer to store plaintext data
     */
    private final byte[] plaintext;

    /**
     * Buffer to store encrypted data
     */
    private final byte[] encrypted;

    /**
     * User key used to encrypt ("User")
     */
    private final AESKey userKey;

    /**
     * Verifier key used to encrypt ("Verifier")
     */
    private final AESKey verifierKey;

    /**
     * Default UserController constructor.
     */
    public UserController() {
        model = new UserModel();
        plaintext = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_RESET); // 5·AES_BLOCK_SIZE
        encrypted = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_RESET); // 5·AES_BLOCK_SIZE

        userKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        verifierKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
    }

    /**
     * Gets the user identifier by copying it to the input buffer at the specified position.
     *
     * @param buffer the input buffer
     * @param offset the offset into input buffer
     */
    public void getIdentifier(byte[] buffer, short offset) {
        Util.arrayCopyNonAtomic(model.getIdentifier(), (short) 0, buffer, offset, Config.USER_MAX_ID_LENGTH);
    }

    /**
     * Sets the user identifier by copying it from the input buffer at the specified position.
     *
     * @param buffer the input buffer
     * @param offset the offset into input buffer
     */
    public void setIdentifier(byte[] buffer, short offset) {
        Util.arrayCopyNonAtomic(buffer, offset, model.getIdentifier(), (short) 0, Config.USER_MAX_ID_LENGTH);
    }

    /**
     * Gets the user nonce by copying it to the input buffer at the specified position.
     *
     * @param buffer the input buffer
     * @param offset the offset into input buffer
     */
    public void getNonce(byte[] buffer, short offset) {
        Util.arrayCopyNonAtomic(model.getNonce(), (short) 0, buffer, offset, Config.NONCE_LENGTH);
    }

    /**
     * Generates the user nonce by cryptographically secure
     * random number generation algorithm.
     */
    public void setNonceByCSRNG() {
        model.setNonceByCSRNG();
    }

    /**
     * Sets the user private key by copying it from the input buffer at the specified position.
     *
     * @param buffer the input buffer
     * @param offset the offset into input buffer
     */
    public void setPrivateKey(byte[] buffer, short offset) {
        model.getKey().setKey(buffer, offset);
    }

    /**
     * Computes the first stage of the user show.
     *
     * @param data     output byte array where the first stage of the user show will be stored
     * @param verifier the verifier controller
     */
    public void computeShowStage1(byte[] data, VerifierController verifier) {
        short offset = 0;
        Cipher cipher;

        // "000000000000User"
        byte[] input = {
                (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
                (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x55, (byte) 0x73, (byte) 0x65, (byte) 0x72
        };

        // compute user_key = AES (k_vi-ui; "User")
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        cipher.init(model.getKey(), Cipher.MODE_ENCRYPT);
        cipher.doFinal(input, (short) 0, Config.AES_BLOCK_SIZE, encrypted, (short) 0);

        // set user_key
        userKey.setKey(encrypted, (short) 0);

        // prepare data to encrypt
        Util.arrayCopyNonAtomic(model.getIdentifier(), (short) 0, plaintext, offset, Config.USER_MAX_ID_LENGTH);
        offset += Config.USER_MAX_ID_LENGTH;
        Util.arrayCopyNonAtomic(verifier.getIdentifier(), (short) 0, plaintext, offset, Config.VERIFIER_MAX_ID_LENGTH);
        offset += Config.VERIFIER_MAX_ID_LENGTH;
        Util.arrayCopyNonAtomic(model.getNonce(), (short) 0, plaintext, offset, Config.NONCE_LENGTH);
        offset += Config.NONCE_LENGTH;
        Util.arrayCopyNonAtomic(verifier.getNonce(), (short) 0, plaintext, offset, Config.NONCE_LENGTH);

        // compute AES (user_key; id_u, id_v, nonce_u, nonce_v)
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(userKey, Cipher.MODE_ENCRYPT);
        cipher.doFinal(plaintext, (short) 0, (short) (4 * Config.AES_BLOCK_SIZE), encrypted, (short) 0);

        // copy iv used to encrypt
        Util.arrayCopyNonAtomic(model.getIV(), (short) 0, data, (short) 0, Config.AES_IV_LENGTH);
        // copy encrypted output
        Util.arrayCopyNonAtomic(encrypted, (short) 0, data, Config.AES_IV_LENGTH, (short) (4 * Config.AES_BLOCK_SIZE));
    }

    /**
     * Computes the second stage of the user show and gets the session key.
     *
     * @param data     input byte array where the verifier cipher output is stored
     * @param verifier the verifier controller
     */
    public void computeShowStage2(byte[] data, VerifierController verifier) {
        Cipher cipher;
        byte r;

        // "00000000Verifier"
        byte[] input = {
                (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
                (byte) 0x56, (byte) 0x65, (byte) 0x72, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x65, (byte) 0x72
        };

        // compute verifier_key = AES (k_vi-ui; "Verifier")
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        cipher.init(model.getKey(), Cipher.MODE_ENCRYPT);
        cipher.doFinal(input, (short) 0, Config.AES_BLOCK_SIZE, encrypted, (short) 0);

        // set verifier_key
        verifierKey.setKey(encrypted, (short) 0);

        // compute AES (verifier_key; id_v, id_u, nonce_v, nonce_u, session_key)
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(verifierKey, Cipher.MODE_DECRYPT);
        cipher.doFinal(data, Config.AES_IV_LENGTH, (short) (5 * Config.AES_BLOCK_SIZE), plaintext, (short) 0);

        // check verifier id
        r = Util.arrayCompare(verifier.getIdentifier(), (short) 0, plaintext, (short) 0, Config.VERIFIER_MAX_ID_LENGTH);
        if (r != 0) {
            ISOException.throwIt(Config.AUTHENTICATION_ERR);
        }

        // check user id
        r = Util.arrayCompare(model.getIdentifier(), (short) 0, plaintext, Config.AES_BLOCK_SIZE, Config.USER_MAX_ID_LENGTH);
        if (r != 0) {
            ISOException.throwIt(Config.AUTHENTICATION_ERR);
        }

        // check verifier nonce
        r = Util.arrayCompare(verifier.getNonce(), (short) 0, plaintext, (short) (2 * Config.AES_BLOCK_SIZE), Config.NONCE_LENGTH);
        if (r != 0) {
            ISOException.throwIt(Config.AUTHENTICATION_ERR);
        }

        // check user nonce
        r = Util.arrayCompare(model.getNonce(), (short) 0, plaintext, (short) (3 * Config.AES_BLOCK_SIZE), Config.NONCE_LENGTH);
        if (r != 0) {
            ISOException.throwIt(Config.AUTHENTICATION_ERR);
        }

        // copy session key
        Util.arrayCopyNonAtomic(plaintext, (short) (4 * Config.AES_BLOCK_SIZE), model.getSessionKey(), (short) 0, Config.AES_BLOCK_SIZE);

        ISOException.throwIt(Config.AUTHENTICATION_OK);
    }
}
