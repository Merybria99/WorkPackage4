package it.unisa.aps.signature_schemes.lrs;

import it.unisa.aps.Utils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * The class implementation is empty or defined with probabilistic outputs as the
 * linkable ring signature scheme implementation was not required to be done as it
 * was not a part of the program, according to what was established with the professor
 * Ivan Visconti.
 */
public class LinkableRingSignature {



    /**
     * The function sets the Public Parameters of the scheme
     * @param n
     */
    public static void setup(int n) {
        SharedData.setPublicParameters(new SecureRandom(Utils.toByteArray(String.valueOf(n))).nextInt());
    }

    /**
     * @param publicParameters
     * @return KeyPair
     * @throws Exception
     */
    public static KeyPair keygen(int publicParameters) throws Exception {
        return Utils.generateKeys(publicParameters);
    }

    /**
     * @param privateKey
     * @param message
     * @param ring
     * @return byte[]
     */
    public static byte[] sign(PrivateKey privateKey, String message, List<PublicKey> ring) {
        byte[] sign_emulator = new byte[256];
        new SecureRandom().nextBytes(sign_emulator);
        return sign_emulator;
    }

    /**
     * The function verifies if the sign provided corresponds with the provided message
     * @param ring the ring specified for the current sign
     * @param message the message to be tested
     * @param sign the sign to be tested
     * @return boolean true if the sign matches, false otherwise
     */
    public static boolean verify(List<PublicKey> ring, String message, byte[] sign) {
        return true;
        // return new SecureRandom().nextFloat() < 0.95;
    }

    /**
     * @param signA
     * @param signB
     * @return boolean
     */
    public static boolean link(byte[] signA, byte[] signB) {
        // DA TRUE SE LINKA FALSE ALTRIMENTI
        // ho messo il segno maggiore per il caso applicativo
        // return new SecureRandom().nextFloat() > 0.5;
        return true;
    }

    /**
     * @param size
     * @return List<PublicKey>
     */
    public static List<PublicKey> getRandomRing(int size) {
        return new ArrayList<>();
        /*
         * List<PublicKey> ring = SharedData.getPublicKeys();
         * Collections.shuffle(ring);
         * int randomIndex=new Random().nextInt(ring.toArray().length-size);
         * return ring.subList(randomIndex,randomIndex+size-1);
         */
    }
}
