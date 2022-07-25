package it.unisa.aps.ssl_connection.client;

import it.unisa.aps.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

public class ClientExecutable {
    /**
     * The main method in this class is used to manage the behaviour of the client,
     * that wants to send requests to the server.
     * Based on the parameters passed by argument, a specific request is sent to the
     * server.
     *
     * @param args represents the modality of operation (generate keypair or create,
     *             modify, view the contract)
     */
    public static void main(String[] args) {
        // the defined algorithm for keys is DSA as the provider does not support
        // ECDSA keys to be saved into key and trust stores
        String algorithm = "DSA";
        Security.addProvider(new BouncyCastleProvider());
        SSLClient client = new SSLClient();

        try {

            client.setServerKey(Utils.getPublicKey("./src/main/resources/trust_store.jks", "entry10", "password"));

            // Loading key data from the file if you are not in generation mode
            if (!args[0].equals("generate"))
                client.setKeyPair(Utils.LoadKeyPair("./src/main/resources/clientInfos", algorithm));
            client.initConnection("localhost", 4000, "./src/main/resources/trust_store.jks", "password" );
            //gets the stream and writes the mode to the server

            ObjectOutputStream outputStream = client.getOutputStream();
            outputStream.writeObject(args[0]);

            //gets a different routine depending on the access mode
            switch (args[0]) {
                case "create" -> client.createProtocol(args[1]);
                case "view" -> {
                    byte[] contractID = Files.readAllBytes(Path.of("src/main/resources/clientInfos/contractId.txt"));
                    client.viewProtocol(contractID);
                    break;
                }
                case "modify" -> {
                    byte[] contractID = Files.readAllBytes(Path.of("src/main/resources/clientInfos/contractId.txt"));
                    client.modifyProtocol(args[1], contractID);
                    break;
                }
                case "generate" -> {
                    client.generateProtocol();
                    break;
                }
            }

        } catch (Exception e) {
            if (e instanceof SocketException)
                System.out.println("Connection ended...");
        }

    }
}
