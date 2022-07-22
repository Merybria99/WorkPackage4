package it.unisa.aps.signature_schemes.fiat_shamir;

import it.unisa.aps.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.Random;

public class FiatShamirSignature {

    /**
     * The function obtains a signature for the plaintext that has in input
     *
     * @param plaintext the message to be signed
     * @return a bytearray that represents the signature for the plaintext
     * @throws Exception
     */
    public static byte[] sign(String plaintext,PrivateKey privateKey) throws Exception {
        Signature ecdsaSign = Signature.getInstance("SHA256withDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext.getBytes("UTF-8"));
        return ecdsaSign.sign();
    }
    public static byte[] sign(byte[] plaintext,PrivateKey privateKey) throws Exception{
        Signature ecdsaSign = Signature.getInstance("SHA256withDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext);
        return ecdsaSign.sign();
    }


    /**
     * The function verifies the correctness of the given signature
     *
     * @param plaintext the message in plaintext
     * @param signature the given signature that has to be verified
     * @return a boolean that is true if the sign is verified , false otherwise
     * @throws Exception
     */
    public  static boolean verify(String plaintext, byte[] signature, PublicKey publicKey) throws Exception {
        Signature ecdsaVerify = Signature.getInstance("SHA256withDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(plaintext.getBytes("UTF-8"));
        return ecdsaVerify.verify(signature);
    }



}
