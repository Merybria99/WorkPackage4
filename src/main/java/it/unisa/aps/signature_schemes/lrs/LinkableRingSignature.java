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
     * @param n represents the security parameter
     */
    public static void setup(int n) {
        SharedData.setPublicParameters(new SecureRandom(Utils.toByteArray(String.valueOf(n))).nextInt());
    }

    /**
     * Given Public Parameters, generates a KeyPair
     * @param publicParameters represents Public Parameters generated in the setup method
     * @return KeyPair represents the KeyPair generated
     * @throws Exception
     */
    public static KeyPair keygen(int publicParameters) throws Exception {
        return Utils.generateKeys(publicParameters);
    }

    /**
     * The following method is used to emulate a firm's signature, in accordance with the proposed
     * Linkable Ring Signature scheme.
     * @param privateKey private key forged according to the Linkable Ring Signature keygen algorithm
     * @param message the message for which you want to get a signature
     * @param ring the ring specified for the current sign
     * @return byte[] provides a vector of bytes representing the signature for the above message
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
        return new SecureRandom().nextFloat() < 0.95;
    }

    /**
     * The function checks if the two signs were produced by the same ring.
     * @param signA the first sign produced with LRS
     * @param signB the second sign produced with LRS
     * @return boolean true if the two signs produced from the same ring, otherwise false
     */
    public static boolean link(byte[] signA, byte[] signB) {
        return new SecureRandom().nextFloat() > 0.5;

    }

    /**The following method makes it possible to logically implement the choice of a ring with random public keys.
     * The implementation is shown even though, since it cannot implement valid keys, it turns out to be simulated.
     * @param size represents the size of the subset of the total Public Keys that you want to obtain
     * @return List<PublicKey> the ring representative of the portion of Public Keys
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
