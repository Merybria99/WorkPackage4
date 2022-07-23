package it.unisa.aps.signature_schemes.lrs;

import it.unisa.aps.Utils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class LinkableRingSignature {

    public static void setup(int n){
        SharedData.setPublicParameters(new SecureRandom(Utils.toByteArray(String.valueOf(n))).nextInt());
    }

    public static KeyPair keygen(int publicParameters)throws Exception{
        return Utils.generateKeys(publicParameters);
    }

    public static byte[] sign(PrivateKey privateKey, String message, List<PublicKey> ring){
        byte[] sign_emulator = new byte[256];
        new SecureRandom().nextBytes(sign_emulator);
        return sign_emulator;
    }

    public static boolean verify(List<PublicKey> ring, String message, byte[] sign){
        return true;
        //return new SecureRandom().nextFloat() < 0.95;
    }

    public static boolean link(byte[] signA, byte[] signB){
        // DA TRUE SE LINKA FALSE ALTRIMENTI
        //ho messo il segno maggiore per il caso applicativo
       // return  new SecureRandom().nextFloat() > 0.5;
        return  true;
    }

    public static List<PublicKey> getRandomRing(int size){
        return new ArrayList<>();
        /*
        List<PublicKey> ring = SharedData.getPublicKeys();
        Collections.shuffle(ring);
        int randomIndex=new Random().nextInt(ring.toArray().length-size);
        return ring.subList(randomIndex,randomIndex+size-1);
        */
    }
}
