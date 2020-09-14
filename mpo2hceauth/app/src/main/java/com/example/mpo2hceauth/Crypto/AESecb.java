/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.mpo2hceauth.Crypto;


import com.example.mpo2hceauth.utils.Convert;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

 
public class AESecb {
 
    
    public static byte [] doEncrypt(byte[] plaintext, byte [] iv, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
       // Cipher cipher = Cipher.getInstance("AES/ECB/pkcs5padding", "SunJCE");
       // Cipher cipher = Cipher.getInstance("AES/ECB/pkcs5padding");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
       // GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte [] doDecrypt(byte [] ciphertext, byte [] iv, SecretKey key)throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
      //  Cipher cipher = Cipher.getInstance("AES/ECB/pkcs5padding");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }
    
    
    public static SecretKey setKey(String myKey) 
    {
    	byte[] keyx = Convert.hexStringToByteArray(myKey);
    	return new SecretKeySpec(keyx, 0, keyx.length, "AES");          
    }
    
     public static SecretKey setKey(byte[] keyx) 
    {   	
    	return new SecretKeySpec(keyx, 0, keyx.length, "AES");          
    }
 
  
}