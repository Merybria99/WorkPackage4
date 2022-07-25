package it.unisa.aps.ssl_connection.server;

import it.unisa.aps.Utils;
import it.unisa.aps.exceptions.VoteNotValidException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLSocket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.SocketException;
import java.security.Security;

public class ServerExecutable {
    /**
     * The main method in this class is used to manage the behaviour of the server
     * in response to the client.
     * The connection is initialised and the server waits for requests from clients.
     *
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        SSLServer server = new SSLServer();

        server.setKeyPair(Utils.getKeyPair("./src/main/resources/key_store.jks", "entry10", "password"));

        server.initConnection(4000, "./src/main/resources/key_store.jks", "password");
        while (true) {
            SSLSocket sslSock = (SSLSocket) server.getSslServerSocket().accept();
            System.out.println("New connection from: " + sslSock.getLocalAddress());

            server.setInputStream(new ObjectInputStream(sslSock.getInputStream()));
            server.setOutputStream(new ObjectOutputStream(sslSock.getOutputStream()));

            String operation = (String) server.getInputStream().readObject();
            try {
                switch (operation) {
                    case "create" -> server.createProtocol();
                    case "view" -> server.viewProtocol();
                    case "modify" -> server.modifyProtocol();
                }
            } catch (VoteNotValidException e) {
                System.out.println(e.getMessage());
                sslSock.close();
            }
        }
    }
}
