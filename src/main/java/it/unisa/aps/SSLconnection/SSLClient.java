package it.unisa.aps.SSLconnection;

import it.unisa.aps.Utils;
import it.unisa.aps.signature_schemes.fiat_shamir.FiatShamirSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ObjectOutputStream;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.Security;


public class SSLClient {
    public SSLSocket sslSocket;

    public void initConnection(String server, int port) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", "./src/main/resources/trust_store.jks");
        System.setProperty("javax.net.ssl.trustStorePassword","password");

        SSLSocketFactory sslSocketFactory= (SSLSocketFactory) SSLSocketFactory.getDefault();

        sslSocket =  (SSLSocket) sslSocketFactory.createSocket(server, port);
        sslSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
        sslSocket.startHandshake();

    }

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());
        SSLClient client = new SSLClient();
        try {
            client.initConnection("localhost",4000);
            ObjectOutputStream out = new ObjectOutputStream(client.sslSocket.getOutputStream());

            KeyPair keys = Utils.getKeyPair("./src/main/resources/key_store.jks", "entry9", "password");
            String message = "messaggio da firmare";
            byte[] sign = FiatShamirSignature.sign(Utils.toByteArray(message), keys.getPrivate());
            out.writeObject(sign);

        } catch (Exception e) {
            if(e instanceof SocketException)
                System.out.println("Connection ended...");
            else
                System.out.println(e.getMessage());
        }

    }
}

