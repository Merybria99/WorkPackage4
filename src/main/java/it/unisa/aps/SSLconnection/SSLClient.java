package it.unisa.aps.SSLconnection;


import it.unisa.aps.Utils;
import it.unisa.aps.exceptions.VoteNotValidException;
import it.unisa.aps.signature_schemes.lrs.LinkableRingSignature;
import it.unisa.aps.signature_schemes.lrs.SharedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.SocketException;
import java.security.*;
import java.util.Collections;
import java.util.List;
import java.util.Random;


public class SSLClient {
    private SSLSocket sslSocket;
    private PublicKey serverKey;
    private KeyPair keyPair;
    private byte[] contractId;

    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;

    public void initConnection(String server, int port) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", "./src/main/resources/trust_store.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        sslSocket = (SSLSocket) sslSocketFactory.createSocket(server, port);
        sslSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
        sslSocket.startHandshake();

        outputStream = new ObjectOutputStream(sslSocket.getOutputStream());
        inputStream = new ObjectInputStream(sslSocket.getInputStream());
    }

    public PublicKey getServerKey() {
        return serverKey;
    }

    public void setServerKey(PublicKey serverKey) {
        this.serverKey = serverKey;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public static void main(String[] args) {
        //definisco l'algoritmo di lettura delle chiavi pari a DSA in quanto java non supporta la creazione di chiavi con LRS
        String algorithm = "DSA";

        Security.addProvider(new BouncyCastleProvider());
        SSLClient client = new SSLClient();
        try {
            client.setServerKey(Utils.getPublicKey("./src/main/resources/trust_store.jks", "entry9", "password"));

            //Carico i dati delle chiavi dal file se non sonon in modalità di generazione
            if (!args[0].equals("generate"))
                client.setKeyPair(Utils.LoadKeyPair("./src/main/resources/clientKeys", algorithm));

            client.initConnection("localhost", 4000);

            client.outputStream.writeObject(args[0]);
            if (args[0].equals("create"))
                client.createProtocol(args[1]);
            else if (args[0].equals("view"))
                client.viewProtocol();
            else if (args[0].equals("modify"))
                client.modifyProtocol(args[1],args[2]);
            else if (args[0].equals("generate"))
                client.generateProtocol();

        } catch (Exception e) {
            if (e instanceof SocketException)
                System.out.println("Connection ended...");
        }

    }

    private void generateProtocol() {
        String keyFolderPath = "./src/main/resources/clientKeys";

        KeyPair keyPair;
        try {
            keyPair = LinkableRingSignature.keygen(SharedData.getPublicParameters());
            System.out.println(keyPair);
            Utils.SaveKeyPair(keyFolderPath, keyPair);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void modifyProtocol(String voteString, String contractId) throws Exception {
        int vote = Integer.parseInt(voteString);
        if(!Utils.isVoteValid(vote))
            throw new VoteNotValidException("Vote is not in range {-1,0,1}");
        String message = "voting " + vote + "on contract " + contractId;

        outputStream.writeObject(message);
        List<PublicKey> ring = LinkableRingSignature.getRandomRing(256);
        ring.add(keyPair.getPublic());
        outputStream.writeObject(ring);
        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);
        outputStream.writeObject(sign);

        byte[] serverResponse = (byte[]) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();

        String messageResponse=Utils.toString(serverResponse);
        System.out.println(messageResponse);

    }

    public void viewProtocol() {

    }

    public void createProtocol(String vote_string) throws Exception {
        int vote = Integer.parseInt(vote_string);
        if(!Utils.isVoteValid(vote))
            throw new VoteNotValidException("Vote is not in range {-1,0,1}");

        String message = "vote request " + vote;
        outputStream.writeObject(message);
        List<PublicKey> ring = LinkableRingSignature.getRandomRing(256);
        ring.add(keyPair.getPublic());
        outputStream.writeObject(ring);
        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);
        outputStream.writeObject(sign);

        // attendo la risposta dal server

        byte[] serverResponse = (byte[]) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();

        String messageResponse=Utils.toString(serverResponse);
        System.out.println(messageResponse);

    }



}

