package it.unisa.aps.SSLconnection;

import it.unisa.aps.Utils;
import it.unisa.aps.signature_schemes.fiat_shamir.FiatShamirSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

public class SSLServer {
    public SSLServerSocket sslServerSocket;


    public void initConnection(int port, String keystorePath, String password) throws Exception {
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", password);

        SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
        sslServerSocket.setEnabledProtocols(new String[]{"TLSv1.2"});

        System.out.println("Init connection...");
    }


    public SSLServerSocket getSslServerSocket() {
        return sslServerSocket;
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        SSLServer server = new SSLServer();
        KeyPair keyPair = Utils.getKeyPair("./src/main/resources/key_store.jks", "entry", "password");
        server.initConnection(4000, "./src/main/resources/key_store.jks", "password");
        while (true){
            SSLSocket sslSock = (SSLSocket) server.getSslServerSocket().accept();
            InputStream input = sslSock.getInputStream();
            ObjectInputStream inputStream = new ObjectInputStream(input);
            System.out.println("New connection from: " + sslSock.getLocalAddress());
            PublicKey publicKey = Utils.getPublicKey("./src/main/resources/trust_store.jks", "entry9", "password");

            while (!sslSock.isClosed()) {
                try {
                    byte[] a = (byte[]) inputStream.readObject();
                    boolean return_value = FiatShamirSignature.verify("messaggio da firmare", a, publicKey);
                    System.out.println(return_value);
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }

            }
            inputStream.close();
        }
    }
}

