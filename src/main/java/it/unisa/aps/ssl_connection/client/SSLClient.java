package it.unisa.aps.ssl_connection.client;

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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

public class SSLClient {
    private SSLSocket sslSocket;
    private PublicKey serverKey;
    private KeyPair keyPair;

    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;

    /***************** CONNECTION OPERATION ******************/

    /**
     * This method initialize the connection client side, then sets up the
     * trustStore and its password, creates the Socket, chooses the protocol
     * to be followed, and starts the handshake phase.
     *
     * @param server             address of the server to which it will connect
     * @param port               the server port to connect to
     * @param trustStorePassword represents the password of the KeyStore
     * @param trustStorePath     represents the path of the KeyStore
     * @throws Exception
     */
    public void initConnection(String server, int port, String trustStorePath, String trustStorePassword) throws Exception {
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);


        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        sslSocket = (SSLSocket) sslSocketFactory.createSocket(server, port);

        sslSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
        sslSocket.startHandshake();

        outputStream = new ObjectOutputStream(sslSocket.getOutputStream());
        inputStream = new ObjectInputStream(sslSocket.getInputStream());

    }

    /***************** GETTER AND SETTER ******************/

    /**
     * @return PublicKey
     */
    public PublicKey getServerKey() {
        return serverKey;
    }

    /**
     * @param serverKey
     */
    public void setServerKey(PublicKey serverKey) {
        this.serverKey = serverKey;
    }

    /**
     * @return KeyPair
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * @param keyPair
     */
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * @return
     */
    public ObjectOutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * @return
     */
    public ObjectInputStream getInputStream() {
        return inputStream;
    }


    /***************** PROTOCOLS ******************/

    /**
     * The following method is used to modify a smart contract already present
     * within the VoteChain.
     * To do this, it checks the validity of the vote and sends the message,
     * in the right format, on the outputStream together with the contractId.
     * It then sends the signature to the Server, waits for a response from it
     * and displays it on the screen.
     * If the response from the Server is negative, then the exception is thrown.
     *
     * @param voteString represents the vote message
     * @param contractId represents the contract ID
     * @throws Exception
     */
    public void modifyProtocol(String voteString, byte[] contractId) throws Exception {
        int vote = Integer.parseInt(voteString);

        if (!Utils.isVoteValid(vote))
            throw new VoteNotValidException("Vote is not in range {-1,0,1}");

        String message = "voting " + vote + " on contract " + Utils.toString(contractId);

        outputStream.writeObject(message);
        outputStream.writeObject(contractId);

        List<PublicKey> ring = Utils.getRing("src/main/resources/clientInfos/ring.txt");
        ring.add(keyPair.getPublic());
        outputStream.writeObject(ring);

        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);
        outputStream.writeObject(sign);

        byte[] serverResponse = (byte[]) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();

        System.out.println(Utils.toString(serverResponse));

        if (!FiatShamirSignature.verify(serverResponse, serverCommit, serverKey)) {
            throw new InvalidCommitException("Fiat Shamir Signature not well formed");
        }

    }

    /**
     * The following method is used to check a smart contract already present
     * within the VoteChain.
     * To do this, it sends the request to the server, entering the message, the
     * contract
     * id and the ring, and signing it. Then, it waits for the response from the
     * server and
     * finally if the verification is successful it displays the contract, otherwise
     * it
     * throws the exception.
     *
     * @param contractId represents the contract ID
     * @throws Exception
     */
    public void viewProtocol(byte[] contractId) throws Exception {
        String message = "rendering " + Utils.toString(contractId);

        outputStream.writeObject(message);
        outputStream.writeObject(contractId);

        List<PublicKey> ring = Utils.getRing("src/main/resources/clientInfos/ring.txt");
        ring.add(keyPair.getPublic());
        outputStream.writeObject(ring);

        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);
        outputStream.writeObject(sign);

        String serverResponse = (String) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();

        if (!FiatShamirSignature.verify(serverResponse, serverCommit, serverKey)) {
            throw new InvalidCommitException("Fiat Shamir Signature not well formed");
        }

        System.out.println("contract is:\n" + serverResponse);

    }

    /**
     * The following method is used to create a smart contract and send it to the
     * server in order to insert it into VoteChain.
     * First, the validity of the vote to be entered is checked, then, the message
     * to be sent to the Server with the checked vote inside is generated.
     * The ring and the id of the contract are saved by the client and the signature
     * is sent by the client to the server. after which the server's response is
     * awaited,
     * and if the result is negative, then an exception is thrown
     *
     * @param voteString
     * @throws Exception
     */
    // COMPLETATE
    public void createProtocol(String voteString) throws Exception {

        int vote = Integer.parseInt(voteString);
        if (!Utils.isVoteValid(vote))
            throw new VoteNotValidException("Vote is not in range {-1,0,1}");

        String message = "vote request " + vote;
        outputStream.writeObject(message);

        List<PublicKey> ring = LinkableRingSignature.getRandomRing(256);
        ring.add(keyPair.getPublic());
        // List<PublicKey> ring= new ArrayList<>();
        outputStream.writeObject(ring);

        // TO SAVE THE RING THE CLIENT IS SUPPOSED TO WRITE IT INTO THE ring.txt FILE
        ObjectOutputStream file = new ObjectOutputStream(
                new FileOutputStream("src/main/resources/clientInfos/ring.txt"));
        file.writeObject(ring);

        byte[] sign = LinkableRingSignature.sign(keyPair.getPrivate(), message, ring);

        // salvo l'id del contratto all'interno del file
        FileOutputStream stream = new FileOutputStream("./src/main/resources/clientInfos/contractId.txt");
        stream.write(sign);
        outputStream.writeObject(sign);

        // attendo la risposta dal server

        byte[] serverResponse = (byte[]) inputStream.readObject();
        byte[] serverCommit = (byte[]) inputStream.readObject();

        if (!FiatShamirSignature.verify(serverResponse, serverCommit, serverKey)) {
            throw new InvalidCommitException("Fiat Shamir Signature not well formed");
        }

        System.out.println("Ended...");
    }

    /**
     * The method is used to generate a keyPair using the keygen function.
     * The method also saves the keyPair to a file.
     */
    public void generateProtocol() {
        String keyFolderPath = "./src/main/resources/clientInfos";
        KeyPair keyPair;
        try {
            keyPair = LinkableRingSignature.keygen(SharedData.getPublicParameters());
            Utils.SaveKeyPair(keyFolderPath, keyPair);
        } catch (Exception e) {}

    }


}
