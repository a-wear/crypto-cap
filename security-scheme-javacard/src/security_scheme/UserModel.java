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

import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;

public class UserModel {

    /**
     * User identifier
     */
    private final byte[] identifier;

    /**
     * User nonce
     */
    private final byte[] nonce;

    /**
     * User private key
     */
    private final AESKey key;

    /**
     * User initialization vector
     */
    private final byte[] iv;

    /**
     * User session key
     */
    private final byte[] sessionKey;

    /**
     * Default UserModel constructor.
     */
    public UserModel() {
        identifier = new byte[Config.USER_MAX_ID_LENGTH]; // persistent
        nonce = JCSystem.makeTransientByteArray(Config.NONCE_LENGTH, JCSystem.CLEAR_ON_RESET);
        key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        iv = JCSystem.makeTransientByteArray(Config.AES_IV_LENGTH, JCSystem.CLEAR_ON_RESET);
        sessionKey = new byte[Config.AES_BLOCK_SIZE]; // persistent
    }

    /**
     * Gets the user identifier.
     *
     * @return the user identifier
     */
    public byte[] getIdentifier() {
        return identifier;
    }

    /**
     * Gets the user nonce.
     *
     * @return the user nonce
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Generates the user nonce by cryptographically secure
     * random number generation algorithm.
     */
    public void setNonceByCSRNG() {
        RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        randomData.generateData(nonce, (short) 0, Config.NONCE_LENGTH);
    }

    /**
     * Gets the user private key.
     *
     * @return the user private key
     */
    public AESKey getKey() {
        return key;
    }

    /**
     * Gets the initialization vector.
     *
     * @return the initialization vector
     */
    public byte[] getIV() {
        return iv;
    }

    /**
     * Gets the session key.
     *
     * @return the session key
     */
    public byte[] getSessionKey() {
        return sessionKey;
    }
}
