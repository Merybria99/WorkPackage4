package it.unisa.aps;

import it.unisa.aps.signature_schemes.lrs.LinkableRingSignature;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import static it.unisa.aps.Utils.generateKeys;

public class ATDManager {


    /**
     * Generate a keypair and insert them into a keystore (.jks file)
     *
     * @param keyStorePath    represents the path of the keystore (.jks file)
     * @param password        represents the keystore's password
     * @param keyPairAlias    represents the alias of the keypair into keystore
     * @param commonName      represents the server name protected by the SSL certificate
     * @param domainComponent represents the domain hierarchy
     * @throws Exception
     */
    public static Certificate generateKeyPairIntoKeyStore(String keyStorePath, String password, String keyPairAlias, String commonName, String domainComponent) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyStore keyStore = KeyStore.getInstance("JKS");

        KeyPair keypair = generateKeys(1024);
        Certificate certificate = generateCertificate(keypair, commonName, domainComponent, 10);

        keyStore.load(new FileInputStream(keyStorePath), password.toCharArray());
        keyStore.setKeyEntry(keyPairAlias, keypair.getPrivate(), password.toCharArray(), new Certificate[]{certificate});
        keyStore.store(new FileOutputStream(keyStorePath), password.toCharArray());
        return certificate;
    }

    /**
     * The function saves the passed certificate to the specified truststore, with the given alias
     * @param truststorePath the path to the truststore file
     * @param alias the name to be visualized for the certificate
     * @param password the password specified for the given trust store
     * @param certificate the certificate to be saved
     * @throws Exception in case the file does not exist
     */
    public static void saveCertificateToTruststore(String truststorePath, String alias,String password,Certificate certificate) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream keystoreFile = new FileInputStream(truststorePath);
        keystore.load(keystoreFile, password.toCharArray());
        keystore.setCertificateEntry(alias,certificate);
        keystore.store(new FileOutputStream(truststorePath),password.toCharArray());
    }

    /**
     * Given a public and private key pair, a certificate associated with this key is created, it should be noted how
     * in this case for simplicity it turns out to be possible to decide only in how many years to make it expire based on the date of creation
     *
     * @param pair            the key pair for which it is required the certificate
     * @param commonName      represents the server name protected by the SSL certificate
     * @param domainComponent represents the domain hierarchy
     * @param year            represents in how many years the certificate is due to expire
     * @return A certificate according to the X509Certificate standard
     * @throws Exception
     */
    static public X509Certificate generateCertificate(KeyPair pair, String commonName, String domainComponent, int year) throws Exception {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal dnName = new X500Principal("cn=" + commonName);

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(new X509Name("dc=" + domainComponent));
        certGen.setIssuerDN(dnName);

        certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 24L * 60 * 60 * 365 * year * 1000));

        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithDSA");
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        return certGen.generate(pair.getPrivate(), "BC");
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        //Certificate certificate= generateKeyPairIntoKeyStore("./src/main/resources/key_store.jks","password","entry9","unisa","unisa");
        //saveCertificateToTruststore("./src/main/resources/trust_store.jks","entry9","password",certificate);
    }



}





