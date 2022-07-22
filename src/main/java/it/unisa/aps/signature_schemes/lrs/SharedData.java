package it.unisa.aps.signature_schemes.lrs;

import java.security.PublicKey;
import java.util.ArrayList;

public class SharedData {

    public static int publicParameters;
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
