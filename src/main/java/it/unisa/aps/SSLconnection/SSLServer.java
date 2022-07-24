package it.unisa.aps.SSLconnection;

import it.unisa.aps.Utils;
import it.unisa.aps.contract.Contract;
import it.unisa.aps.exceptions.VoteNotValidException;
import it.unisa.aps.signature_schemes.fiat_shamir.FiatShamirSignature;
import it.unisa.aps.signature_schemes.lrs.LinkableRingSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class SSLServer {
    private SSLServerSocket sslServerSocket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private KeyPair keyPair;

    /***************** SOCKET AND CONNECTION OPERATIONS ******************/

    /**
     * This method initializes the connection server side, so it saves the keystore
     * path and password in the respective environment variables, then creates a
     * socket with the port equals to the parameter passed to the function
     *
     * @param port         represents the port of the socket
     * @param keystorePath represents the path of the keystore (.jks)
     * @param password     represents the password of the keystore
     * @throws Exception
     */
    public void initConnection(int port, String keystorePath, String password) throws Exception {
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", password);

        SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
        sslServerSocket.setEnabledProtocols(new String[] { "TLSv1.2" });

        System.out.println("Init connection...");
    }

    /**
     * This method returns the socket set during the connection initializing.
     *
     * @return SSLServerSocket represents the socket initialized before
     */
    public SSLServerSocket getSslServerSocket() {
        return sslServerSocket;
    }

    /***************** SERVER KEY PAIR MANAGEMENTS ******************/

    /**
     * This method return the server's keypair
     *
     * @return KeyPair of the server
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * This method set the server's keypair
     *
     * @param keyPair represents the sk and pk of the server
     */
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /***************** PROTOCOLS ******************/

    /**
     * This method represents the protocol we designed for verifying the client's
     * request to create a new smart contract; then, if the verification is
     * successful, the contract is created and added to the VoteChain
     *
     * The verification consists of 4 steps:
     * 1) verifies that the vote is -1,0 or 1, thus is well-formed
     * 2) verifies that the ring chosen by the client is included in the set of all
     * existing pk
     * 3) verification of the validity of the signature using LRS
     * 4) verification of the presence of other smart contracts in the VoteChain
     * related to the same client
     *
     * @throws Exception
     */
    private void createProtocol() throws Exception {
        String message = (String) inputStream.readObject();
        List<PublicKey> ring = (List<PublicKey>) inputStream.readObject();
        byte[] sign = (byte[]) inputStream.readObject();

        String[] tmp = message.split(" ");
        String vote_string = tmp[tmp.length - 1];
        int vote = Integer.parseInt(vote_string);

        // Step 1
        if (!Utils.isVoteValid(vote)) {
            String response = "vote is not in valid format";
            outputStream.writeObject(Utils.toByteArray(response));
            outputStream.writeObject(FiatShamirSignature.sign(Utils.toByteArray(response), keyPair.getPrivate()));
            return;
        }

        byte[] response = createResponse(sign, message, vote);
        outputStream.writeObject(response);
        outputStream.writeObject(FiatShamirSignature.sign(response, keyPair.getPrivate()));

        // Step 2
        if (!isRingIncluded(ring))
            throw new VoteNotValidException("Ring not supported for signature");

        // Step 3
        if (!LinkableRingSignature.verify(ring, message, sign))
            throw new VoteNotValidException("Linkable Ring Signature verify fails");

        // Step 4
        FileInputStream fis = new FileInputStream("src/main/resources/VoteChain.txt");
        try {
            ObjectInputStream ois = new ObjectInputStream(fis);
            Contract readContract = null;
            while ((readContract = (Contract) ois.readObject()) != null)
                if (LinkableRingSignature.link(readContract.getContractId(), sign))
                    throw new VoteNotValidException("There is another contract yet");
        } catch (EOFException | StreamCorruptedException e) {
        }

        // Adding contract to the VoteChain
        writeContractOnVoteChain(sign, vote);

    }

    private void viewProtocol() {

    }

    /**
     * This method represents the protocol we designed for verifying the client's
     * request to modify an existing smart contract; then, if the verification is
     * successful, the contract is modified as requested by the client
     *
     * The verification consists of 3 steps:
     * 1) verifies that the vote is -1,0 or 1, thus is well-formed
     * 2) verification of the validity of the signature using LRS
     * 3) verification of the presence of this smart contracts in the VoteChain
     *
     * @throws Exception
     */
    private void modifyProtocol() throws Exception {

        String message = (String) inputStream.readObject();
        byte[] contractId = (byte[]) inputStream.readObject();
        List<PublicKey> ring = (List<PublicKey>) inputStream.readObject();
        byte[] sign = (byte[]) inputStream.readObject();

        String[] tmp = message.split(" ", -1);
        System.out.println(Arrays.stream(tmp).toList());
        String vote_string = tmp[1];
        int vote = Integer.parseInt(vote_string);

        // Step 1
        if (!Utils.isVoteValid(vote)) {
            String response = "vote is not in valid format";
            outputStream.writeObject(Utils.toByteArray(response));
            outputStream.writeObject(FiatShamirSignature.sign(Utils.toByteArray(response), keyPair.getPrivate()));
            return;
        }
        // Step 2
        if (!LinkableRingSignature.verify(ring, message, sign))
            throw new VoteNotValidException("Linkable Ring Signature verify fails");
        // Step3
        if (!LinkableRingSignature.link(contractId, sign))
            throw new VoteNotValidException("Not linking contract Id");

        // Contract modification and VoteChain update
        Timestamp timestamp = new Timestamp(new Date().getTime());
        byte[] oldSign = modifyContractOnVoteChain(contractId, vote, sign, timestamp);

        String response = "change " + oldSign + " on " + contractId + " at " + timestamp;
        byte[] modifyResponse = concatByteArrays(Utils.toByteArray("change "), sign,
                Utils.toByteArray(" on "), contractId,
                Utils.toByteArray(" at " + timestamp));
        outputStream.writeObject(modifyResponse);
        outputStream.writeObject(FiatShamirSignature.sign(Utils.toByteArray(response), keyPair.getPrivate()));

    }

    /***************** VOTECHAIN OPERATIONS ******************/

    /**
     * This method update a contract in the VoteChain file
     *
     * @param contractId represents the ID of the contracts you want to modify
     * @param vote       represents the new vote
     * @param sign       represents the new sign
     * @param timestamp  represents the current timestamp
     * @return byte[] represents the old sign of the contract
     * @throws Exception
     */
    private byte[] modifyContractOnVoteChain(byte[] contractId, int vote, byte[] sign, Timestamp timestamp)
            throws Exception {
        byte[] oldSign = new byte[0];
        ArrayList<Contract> contracts = new ArrayList<>();
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("./src/main/resources/VoteChain.txt"));
        Contract readContract = null;
        try {
            while ((readContract = (Contract) ois.readObject()) != null) {
                if (readContract.getContractId().equals(contractId)) {
                    oldSign = readContract.getSign();
                    readContract.update(vote, timestamp, sign);

                }
                contracts.add(readContract);
            }
        } catch (EOFException | StreamCorruptedException e) {
        }
        ois.close();

        ObjectOutputStream ous = new ObjectOutputStream(new FileOutputStream("./src/main/resources/VoteChain.txt"));
        for (Contract item : contracts) {
            ous.writeObject(item);
        }
        ous.close();
        return oldSign;
    }

    /**
     * This method add a contract in the VoteChain file
     *
     * @param sign represents the sign
     * @param vote represents the vote
     * @throws IOException
     */
    private void writeContractOnVoteChain(byte[] sign, int vote) throws IOException {
        Contract contract = new Contract(sign, vote, new Timestamp(new Date().getTime()));
        FileOutputStream fos = new FileOutputStream("src/main/resources/VoteChain.txt", true);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(contract);
    }

    /***************** OPERATIONS ON BYTE ARRAYS ******************/

    /**
     * This method creates and returns a byte array for responding the client after
     * the creation phase
     *
     * @param sign    represents the sign of the smart contract
     * @param message NON SERVE???????
     * @param vote    represents the vote
     * @return byte[] byte array of the response
     * @throws IOException
     */
    private byte[] createResponse(byte[] sign, String message, int vote) throws IOException {

        Timestamp timestamp = new Timestamp(new Date().getTime());

        byte[] first_part = Utils.toByteArray("checking ");
        byte[] second_part = Utils.toByteArray(" in 24h from " + timestamp + ", then voting " + vote);
        return concatByteArrays(first_part, sign, second_part);
    }

    /**
     * @param a represents byte arrays you want to concatenate
     * @return byte[] byte arrays concatenated
     * @throws IOException
     */
    private byte[] concatByteArrays(byte[]... a) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (byte[] tmp : a) {
            stream.write(tmp);
        }
        return stream.toByteArray();
    }

    /***************** LRS OPERATIONS ******************/

    /**
     * @param ring represents the ring you want to check if it is included in the
     *             total of public keys
     * @return boolean 1 if is included, 0 if not
     */
    public boolean isRingIncluded(List<PublicKey> ring) {
        return true;
        // THIS IMPLEMENTATION HAS NOT REALLY BEEN CARRIED OUT SINCE THE WHOLE LIST OF
        // PUBLIC KEYS IS NOT AVAILABLE

        // List<PublicKey> publicKeys=SharedData.getPublicKeys();
        // return publicKeys.containsAll(ring);
    }

    /***************** MAIN ******************/

    /**
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        SSLServer server = new SSLServer();
        server.setKeyPair(Utils.getKeyPair("./src/main/resources/key_store.jks", "entry9", "password"));
        server.initConnection(4000, "./src/main/resources/key_store.jks", "password");
        while (true) {
            SSLSocket sslSock = (SSLSocket) server.getSslServerSocket().accept();
            System.out.println("New connection from: " + sslSock.getLocalAddress());

            server.inputStream = new ObjectInputStream(sslSock.getInputStream());
            server.outputStream = new ObjectOutputStream(sslSock.getOutputStream());

            String operation = (String) server.inputStream.readObject();

            if (operation.equals("create"))
                server.createProtocol();
            else if (operation.equals("view"))
                server.viewProtocol();
            else if (operation.equals("modify"))
                server.modifyProtocol();

        }
    }

}
