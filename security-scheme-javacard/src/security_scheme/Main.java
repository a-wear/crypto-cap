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

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

/**
 * Security Scheme.
 */
public class Main extends Applet implements ExtendedLength {

    private static final byte CLA_APPLICATION = (byte) 0x80;

    private static final byte INS_SET_USER_IDENTIFIER_PRIVATE_KEY = 0x00;

    private static final byte INS_GET_USER_IDENTIFIER_NONCE = 0x01;
    private static final byte INS_SET_VERIFIER_IDENTIFIER_NONCE = 0x02;

    private static final byte INS_COMPUTE_SHOW_STAGE_1 = 0x03;
    private static final byte INS_COMPUTE_SHOW_STAGE_2 = 0x04;

    /**
     * User controller
     */
    private final UserController user;

    /**
     * Verifier controller
     */
    private final VerifierController verifier;

    private final byte[] data;
    private short offset;

    /**
     * Default constructor.
     *
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    private Main(byte[] bArray, short bOffset, byte bLength) {
        register();

        user = new UserController();
        verifier = new VerifierController();

        data = new byte[128];
        offset = 0;
    }

    /**
     * To create an instance of the Applet subclass, the Java Card runtime environment will call this
     * static method first.
     *
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     * @throws ISOException if the install method failed
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new Main(bArray, bOffset, bLength);
    }

    /**
     * Called by the Java Card runtime environment to process an incoming APDU command. An applet
     * is expected to perform the action requested and return response data if any to the terminal.
     *
     * @param apdu the incoming APDU object
     * @throws ISOException with the response bytes per ISO 7816-4
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (selectingApplet()) {
            return;
        }

        if (cla != CLA_APPLICATION) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_SET_USER_IDENTIFIER_PRIVATE_KEY: {
                try {
                    offset = 0;
                    Util.arrayFillNonAtomic(data, offset, (short) data.length, (byte) 0);

                    receive(apdu); // receive data

                    user.setIdentifier(data, (short) 0); // offset = 0
                    user.setPrivateKey(data, Config.USER_MAX_ID_LENGTH); // offset = Config.USER_MAX_ID_LENGTH
                } catch (APDUException exception) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                break;
            }
            case INS_GET_USER_IDENTIFIER_NONCE: {
                try {
                    user.setNonceByCSRNG();

                    user.getIdentifier(buffer, (short) 0);
                    user.getNonce(buffer, Config.USER_MAX_ID_LENGTH);
                    apdu.setOutgoingAndSend((short) 0, (short) (Config.USER_MAX_ID_LENGTH + Config.NONCE_LENGTH));
                } catch (APDUException exception) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                break;
            }
            case INS_SET_VERIFIER_IDENTIFIER_NONCE: {
                try {
                    offset = 0;
                    Util.arrayFillNonAtomic(data, offset, (short) data.length, (byte) 0);

                    receive(apdu); // receive data

                    verifier.initialize(data);
                } catch (APDUException exception) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                break;
            }
            case INS_COMPUTE_SHOW_STAGE_1: {
                try {
                    offset = 0;
                    Util.arrayFillNonAtomic(data, offset, (short) data.length, (byte) 0);

                    user.computeShowStage1(data, verifier);

                    send(apdu); // send data
                } catch (APDUException exception) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                break;
            }
            case INS_COMPUTE_SHOW_STAGE_2: {
                try {
                    offset = 0;
                    Util.arrayFillNonAtomic(data, offset, (short) data.length, (byte) 0);

                    receive(apdu); // receive data

                    user.computeShowStage2(data, verifier);
                } catch (APDUException exception) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                break;
            }
            default: {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

                break;
            }
        }
    }

    /**
     * Sends the data, this method works in both T0 and T1.
     *
     * @param apdu the incoming APDU object
     * @throws APDUException with the reason code
     */
    private void send(APDU apdu) throws APDUException {
        short sendLength;

        short blockSize = APDU.getOutBlockSize();

        // set outgoing
        short bytesLeft = apdu.setOutgoing();
        apdu.setOutgoingLength(bytesLeft);

        // send data
        while (bytesLeft > 0) {
            sendLength = (blockSize < bytesLeft ? blockSize : bytesLeft);
            apdu.sendBytesLong(data, offset, sendLength);
            offset += sendLength;

            bytesLeft -= sendLength;
        }
    }

    /**
     * Receives the data, this method works in both T0 and T1.
     *
     * @param apdu the incoming APDU object
     * @throws APDUException with the reason code
     */
    private void receive(APDU apdu) throws APDUException {
        byte[] buffer = apdu.getBuffer();

        short bufferOffset = apdu.getOffsetCdata();

        // set incoming and receive first data
        short recvLength = apdu.setIncomingAndReceive();
        Util.arrayCopyNonAtomic(buffer, bufferOffset, data, offset, recvLength);
        offset += recvLength;

        // receive more data if available
        short bytesLeft = apdu.getIncomingLength();
        bytesLeft -= recvLength;

        while (bytesLeft > 0) {
            recvLength = apdu.receiveBytes((short) 0); // read more APDU data
            Util.arrayCopyNonAtomic(buffer, (short) 0, data, offset, recvLength);
            offset += recvLength;

            bytesLeft -= recvLength;
        }
    }
}
