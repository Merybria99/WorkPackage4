package it.unisa.aps;

import java.io.FileInputStream;
import java.security.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class Utils {

    public static String toHex(byte[] data, int length) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;
            String digits = "0123456789abcdef";
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }


    public static SecretKey createKeyForAES(SecureRandom random) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128, random);
        return generator.generateKey();
    }

    public static IvParameterSpec createCtrIvForAES(SecureRandom random) {
        byte[] ivBytes = new byte[16];
        // initially randomize
        random.nextBytes(ivBytes);
        // set the counter bytes to 0
        for (int i = 0; i != 8; i++) {
            ivBytes[8 + i] = 0;
        }
        return new IvParameterSpec(ivBytes);
    }

    public static String toString(
            byte[] bytes,
            int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(
            byte[] bytes,
            int from, int length) {
        char[] chars = new char[length];

        for (int i = from; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(
            byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    public static byte[] toByteArray(
            String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }
        return bytes;
    }

    /*
    * -------------------------------------------
    *             NOSTRE IMPLEMENTAZIONI
    *--------------------------------------------
    * */

    /**
     * The function gets a KeyPair from a keystore referring to a specific alias
     * @param keystorePath the path to the keystore folder
     * @param alias the alias name of the keystore entry
     * @param password the password of the keystore
     * @return teh KeyPair of the corresponding alias
     * @throws Exception
     */
    public static KeyPair getKeyPair(String keystorePath , String alias, String password) throws Exception{
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystorePath), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
        PublicKey publicKey = keystore.getCertificate(alias).getPublicKey();
        return  new KeyPair(publicKey,privateKey);
    }

    /**
     * The function gets the public key from the keystore, referring to a particular alias name
     * @param keystorePath the path to the keystore folder
     * @param alias the alias name of the keystore entry
     * @param password the password of the keystore
     * @return the PublicKey of the corresponding alias
     * @throws Exception
     */
    public static PublicKey getPublicKey(String keystorePath , String alias, String password) throws Exception{
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystorePath), password.toCharArray());
        return keystore.getCertificate(alias).getPublicKey();

    }

    /**
     * The function generates a KeyPair of public and private keys which can be used to sign m256withDSA protocol
     * @return the KeyPair of generated keys
     * @throws Exception
     */
    public static KeyPair generateKeys(int keysize) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "BC");
        g.initialize(keysize, new SecureRandom());
        return g.generateKeyPair();
    }


}