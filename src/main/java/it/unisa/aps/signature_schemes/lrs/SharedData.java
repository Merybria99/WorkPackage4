package it.unisa.aps.signature_schemes.lrs;

import java.security.PublicKey;
import java.util.ArrayList;

/**
 * The function represents the abstraction of a public database from which the client could take
 * the parameters in order to execute the protocol.
 */
public class SharedData {

    public static int publicParameters = 1024;
    public static ArrayList<PublicKey> publicKeys;

    public static int getPublicParameters(){
        return publicParameters;
    }

    public static void setPublicParameters(int publicParameters) {
        SharedData.publicParameters = publicParameters;
    }

    public static ArrayList<PublicKey> getPublicKeys() {
        return publicKeys;
    }
}
