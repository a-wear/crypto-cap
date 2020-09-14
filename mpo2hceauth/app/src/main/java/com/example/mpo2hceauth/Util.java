package com.example.mpo2hceauth;

import java.math.BigInteger;

/**
 * Created by Petr Dzurenda on 26.08.2015.
 */
public class Util {

    /**
     * Convert BigInteger number to byte array
     * @param Bi    BigInteger number
     * @return  byte array
     */
    public static byte[] bigIntegerToByteArray(BigInteger Bi){

        byte[] bBi = Bi.toByteArray();
        byte[] rBi = new byte[bBi.length-1];
        System.arraycopy(bBi, 1, rBi, 0, bBi.length-1);

        return rBi;
    }


    /**
     * Comparison of two byte arrays
     * @param array1    first byte array
     * @param array2    second byte array
     * @return  true if arrays are same, false otherwise
     */
    public static boolean arrayCompare(byte[] array1, byte[] array2){

        boolean result = true;

        if(array1.length == array2.length)
            for(int i=0; i<array1.length; i++) {
                if (array1[i] != array2[i]) {
                    result = false;
                    break;
                }
            }
        else
            result = false;

        return result;
    }


    /**
     * Combines two array into one (depends on the order of arrays)
     * @param array1    first byte array
     * @param array2    second byte array
     * @return  Combined array (array1 || array2)
     */
    public static byte[] arrayCombine(byte[] array1, byte[] array2){

        byte[] arrayCombined = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, arrayCombined, 0, array1.length);
        System.arraycopy(array2, 0, arrayCombined, array1.length, array2.length);

        return arrayCombined;
    }


    /**
     * Conversion byte array to the hexadecimal string
     * @param bytes byte array
     * @return  hexadecimal string
     */
    public static String bytesToHex(byte[] bytes) {

        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
