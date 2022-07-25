package it.unisa.aps;

import it.unisa.aps.exceptions.VoteNotValidException;
import it.unisa.aps.ssl_connection.client.SSLClient;
import it.unisa.aps.ssl_connection.server.SSLServer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Utils extends SSLServer {

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
     * OUR IMPLEMENTATIONS
     * --------------------------------------------
     */

    /**
     * The function gets a KeyPair from a keystore referring to a specific alias
     *
     * @param keystorePath the path to the keystore folder
     * @param alias        the alias name of the keystore entry
     * @param password     the password of the keystore
     * @return teh KeyPair of the corresponding alias
     * @throws Exception
     */
    public static KeyPair getKeyPair(String keystorePath, String alias, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystorePath), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
        PublicKey publicKey = keystore.getCertificate(alias).getPublicKey();
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * The function gets the public key from the keystore, referring to a particular
     * alias name
     *
     * @param keystorePath the path to the keystore folder
     * @param alias        the alias name of the keystore entry
     * @param password     the password of the keystore
     * @return the PublicKey of the corresponding alias
     * @throws Exception
     */
    public static PublicKey getPublicKey(String keystorePath, String alias, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystorePath), password.toCharArray());
        return keystore.getCertificate(alias).getPublicKey();

    }

    /**
     * The function generates a KeyPair of public and private keys which can be used
     * to sign sha256withDSA protocol
     *
     * we chose to use DSA as ECDSA was unsupported for the key and trust stores.
     *
     * @return the KeyPair of generated keys
     * @throws Exception
     */
    public static KeyPair generateKeys(int keysize) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA");
        g.initialize(keysize, new SecureRandom());
        return g.generateKeyPair();
    }

    /**
     * This method saves a given keypair to a file
     * @param path represents the path of the keypair file (.key)
     * @param keyPair represents the keypair you want to save
     * @throws Exception
     */
    public static void SaveKeyPair(String path, KeyPair keyPair) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/public.key");
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        fos = new FileOutputStream(path + "/private.key");
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    /**
     * The functions loadsthe key pair into a key file in order to make it available for the client
     *
     * @param path represents the path where keypair is stored
     * @param algorithm represents the algorithm used for keypair
     * @return
     * @throws Exception
     */
    public static KeyPair LoadKeyPair(String path, String algorithm) throws Exception {
        // Read Public Key.
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(path + "/private.key");
        fis = new FileInputStream(path + "/private.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * The function checks if the vote is in the correct range of values
     * @param vote the number representing the vote
     * @return notifies true if the vote is in the correct range, false otherwise
     * @throws VoteNotValidException
     */
    public static boolean isVoteValid(int vote) throws VoteNotValidException {
        return ((vote >= -1 && vote <= 1));

    }

    /**
     * This method accesses a file in which the applicant's own private key ring,
     * already correctly saved on first access, is saved.
     *
     * The file is not correctly implemented as the correct type for linkable ring signature public keys was not
     * supported by Java
     *
     * @param filePath the path of the file containing the ring
     */
    public static List<PublicKey> getRing(String filePath){
        return new ArrayList<>();
    }
}
