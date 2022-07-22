package it.unisa.aps.SSLconnection;

import it.unisa.aps.Utils;
import it.unisa.aps.contract.Contract;
import it.unisa.aps.exceptions.VoteNotValidException;
import it.unisa.aps.signature_schemes.fiat_shamir.FiatShamirSignature;
import it.unisa.aps.signature_schemes.lrs.LinkableRingSignature;
import it.unisa.aps.signature_schemes.lrs.SharedData;
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
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public class SSLServer {
    private SSLServerSocket sslServerSocket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private KeyPair keyPair;

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
        server.setKeyPair(Utils.getKeyPair("./src/main/resources/key_store.jks", "entry", "password"));
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

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    private void modifyProtocol() {
    }


    private void viewProtocol() {

    }

    private void createProtocol() throws Exception {

        String message = (String) inputStream.readObject();
        List<PublicKey> ring = (List<PublicKey>) inputStream.readObject();
        byte[] sign = (byte[]) inputStream.readObject();


        String[] tmp = message.split(" ");
        String vote_string = tmp[tmp.length - 1];
        int vote = Integer.parseInt(vote_string);

        //CONTROLLO DEL VOTO BEN FORMATO
        if (!Utils.isVoteValid(vote)) {
            String response = "vote is not in valid format";
            outputStream.writeObject(Utils.toByteArray(response));
            outputStream.writeObject(FiatShamirSignature.sign(Utils.toByteArray(response), keyPair.getPrivate()));
            return;
        }

        byte[] response = createResponse(sign, message, vote);
        outputStream.writeObject(response);
        outputStream.writeObject(FiatShamirSignature.sign(response, keyPair.getPrivate()));


        //Verificare se R appartiene all'insieme
        if (!isRingIncluded(ring))
            throw new VoteNotValidException("Ring not supported for signature");

        //FARE LA VERIFY DELLA LINK
        if (!LinkableRingSignature.verify(ring, message, sign))
            throw new VoteNotValidException("Linkable Ring Signature verify fails");

        //LINK CON TUTTI E DEVE FALLIRE
        FileInputStream fis = new FileInputStream("src/main/resources/VoteChain.txt");
        try {
            ObjectInputStream ois = new ObjectInputStream(fis);
            Contract readContract= null;
            while ((readContract = (Contract) ois.readObject())!=null)
                if (LinkableRingSignature.link(readContract.getContractId(), sign))
                    throw new VoteNotValidException("There is another contract yet");
        } catch (EOFException e) {}

        //SCRITTURA SULLA BC

        writeContractOnVoteChain(sign, vote);

    }

    private void writeContractOnVoteChain(byte[] sign, int vote) throws IOException {
        Contract contract = new Contract(sign, vote, new Timestamp(new Date().getTime()));
        FileOutputStream fos = new FileOutputStream("src/main/resources/VoteChain.txt");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(contract);
    }

    private byte[] createResponse ( byte[] sign, String message,int vote) throws IOException {

            Timestamp timestamp = new Timestamp(new Date().getTime());

            byte[] first_part = Utils.toByteArray("checking ");
            byte[] second_part = Utils.toByteArray(" in 24h from " + timestamp + ", then voting " + vote);
            return concatByteArrays(first_part, sign, second_part);
        }

        private byte[] concatByteArrays ( byte[]...a) throws IOException {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (byte[] tmp : a) {
                stream.write(tmp);
            }
            return stream.toByteArray();
        }
        public boolean isRingIncluded (List < PublicKey > ring) {
            return true;
            // List<PublicKey> publicKeys=SharedData.getPublicKeys();
            // return publicKeys.containsAll(ring);
        }

    }
