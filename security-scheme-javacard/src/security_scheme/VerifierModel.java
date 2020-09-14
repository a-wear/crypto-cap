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

public class VerifierModel {

    /**
     * Verifier identifier
     */
    private final byte[] identifier;

    /**
     * Verifier nonce
     */
    private final byte[] nonce;

    /**
     * Default VerifierModel constructor.
     */
    public VerifierModel() {
        identifier = JCSystem.makeTransientByteArray(Config.VERIFIER_MAX_ID_LENGTH, JCSystem.CLEAR_ON_RESET);
        nonce = JCSystem.makeTransientByteArray(Config.NONCE_LENGTH, JCSystem.CLEAR_ON_RESET);
    }

    /**
     * Gets the verifier identifier.
     *
     * @return the verifier identifier
     */
    public byte[] getIdentifier() {
        return identifier;
    }

    /**
     * Gets the verifier nonce.
     *
     * @return the verifier nonce
     */
    public byte[] getNonce() {
        return nonce;
    }
}
