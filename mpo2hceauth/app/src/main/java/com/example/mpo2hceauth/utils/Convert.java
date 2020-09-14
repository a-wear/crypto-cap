/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.mpo2hceauth.utils;

import java.math.BigInteger;

/**
 *
 * @author dzurenda
 */
public class Convert {
    
      /**
     * Convert bytes to hexadecimal string
     * @param bytes
     * @return 
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
    
        /**
     * Convertation Big Integer number to byte array without first byte specified significance
     * @param bigInt
     * @return 
     */
    public static byte[] bigIntToByteArray(BigInteger bigInt){


        byte[] directArray = bigInt.toByteArray();
        byte[] bigIntArray = new byte[directArray.length-1];

        if(directArray[00] == (byte) 0x00){
            System.arraycopy(directArray, 1, bigIntArray, 0, bigIntArray.length);
            return bigIntArray;}
        else
            return directArray;

    }
    
    public static BigInteger byteArrayToBigInt(byte[] array){
        
        byte[] directArray = new byte[array.length+1];
        
        System.arraycopy(array, 0, directArray, 1, array.length);
        directArray[0] = (byte) 0x00;
            
        return new BigInteger(directArray);
    }
    
    
    public String bytesToHexPrint(byte[] bytes) {

        int i = -2;
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 4];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
            
            System.out.print("0x"+hexChars[j * 2]+hexChars[j * 2 + 1]+", ");
        } 
        System.out.println("");
        return new String(hexChars);
    }
    

	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

    public static int byteToHex(byte b){
        int i = b & 0xFF;
        return i;
    }
    
    
    
}
