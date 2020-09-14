/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.mpo2hceauth.Crypto;

import com.example.mpo2hceauth.utils.Convert;

import java.math.BigInteger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


/**
 *
 * @author dzurenda
 */
public class ECCOP_Elliptic_curves {

    private ECParameterSpec ecSpec;
    private ECCurve curve;  
    private ECPoint G;
    private BigInteger q;

    
    public ECCOP_Elliptic_curves(){
       /*
        ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        curve = ecSpec.getCurve();    
        G = ecSpec.getG();
        q = curve.getOrder();
       */

        curve = new ECCurve.Fp(
                new BigInteger("16798108731015832284940804142231733909889187121439069848933715426072753864723"), // q
                new BigInteger("0", 16), // a
                new BigInteger("2", 16)); // b

        ecSpec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("042523648240000001BA344D80000000086121000000000013A7000000000000120000000000000000000000000000000000000000000000000000000000000001")), // G
                new BigInteger("16798108731015832284940804142231733909759579603404752749028378864165570215949")); // n

        G = ecSpec.getG();
        q = new BigInteger("16798108731015832284940804142231733909759579603404752749028378864165570215949");



        System.out.println("G: " + Convert.bytesToHex(G.getEncoded(false)));
    }

    public ECPoint getG() {
        return G;
    }

    public BigInteger getQ() {
        return q;
    }

    public ECCurve getCurve() {
        return curve;
    }
    
    
    
    
    
    
}
