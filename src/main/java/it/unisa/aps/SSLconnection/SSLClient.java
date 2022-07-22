package it.unisa.aps.SSLconnection;


import it.unisa.aps.Utils;
import it.unisa.aps.exceptions.InvalidCommitException;
import it.unisa.aps.exceptions.VoteNotValidException;
import it.unisa.aps.signature_schemes.fiat_shamir.FiatShamirSignature;
import it.unisa.aps.signature_schemes.lrs.LinkableRingSignature;
import it.unisa.aps.signature_schemes.lrs.SharedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Collections;
import java.util.List;
import java.util.Random;


public class SSLClient {
    private SSLSocket sslSocket;
    private PublicKey serverKey;
    private KeyPair keyPair;

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
            else if (args[0].equals("view")){
                byte[] contractID = Files.readAllBytes(Path.of("src/main/resources/ContractId.txt"));
                client.viewProtocol();
            }
            else if (args[0].equals("modify")){
                byte[] contractID = Files.readAllBytes(Path.of("src/main/resources/ContractId.txt"));
                client.modifyProtocol(args[1], contractID);
            }
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

    public void modifyProtocol(String voteString, byte[] contractId) throws Exception {
        int vote = Integer.parseInt(voteString);
        if(!Utils.isVoteValid(vote))
            throw new VoteNotValidException("Vote is not in range {-1,0,1}");

        String message = "voting " + vote + "on contract " + Utils.toString(contractId);

        outputStream.writeObject(message);
        outputStream.writeObject(contractId);

        List<PublicKey> ring = LinkableRingSignature.getRandomRing(256);
        ring.add(keyPair.getPublic());

        outputStream.writeObject(ring);
        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);
        outputStream.writeObject(sign);

        byte[] serverResponse = (byte[]) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();

        if (!FiatShamirSignature.verify(serverResponse,serverCommit,serverKey)){
            throw new InvalidCommitException("Fiat Shamir Signature not well formed");
        }


    }

    public void viewProtocol() {

    }

    public void createProtocol(String voteString) throws Exception {
        int vote = Integer.parseInt(voteString);
        if(!Utils.isVoteValid(vote))
            throw new VoteNotValidException("Vote is not in range {-1,0,1}");

        String message = "vote request " + vote;
        outputStream.writeObject(message);

        List<PublicKey> ring = LinkableRingSignature.getRandomRing(256);
        ring.add(keyPair.getPublic());
        outputStream.writeObject(ring);

        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);

        //salvo l'id del contratto all'interno del file
        try (FileOutputStream stream = new FileOutputStream("src/main/resources/ContractId.txt")) {
            stream.write(sign);
        }
        outputStream.writeObject(sign);

        // attendo la risposta dal server

        byte[] serverResponse = (byte[]) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();


        if (!FiatShamirSignature.verify(serverResponse,serverCommit,serverKey)){
            throw new InvalidCommitException("Fiat Shamir Signature not well formed");
        }

        System.out.println("Ended...");
    }



}

