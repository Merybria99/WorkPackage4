package it.unisa.aps.signature_schemes.lrs;

import it.unisa.aps.Utils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;

public class LinkableRingSignature {
    private List<PublicKey> ring;
    private SecureRandom secureRandom = new SecureRandom();

    public LinkableRingSignature(List<PublicKey> ring) {
        this.ring = ring;
    }

    public int setup(int n){
        return secureRandom.nextInt(n);
    }

    public KeyPair keygen(int publicParameters)throws Exception{
        return Utils.generateKeys(publicParameters);
    }

    public List<PublicKey> getRing() {
        return ring;
    }

    public byte[] sign(PrivateKey privateKey, String message, List<PublicKey> ring){
        byte[] sign_emulator = new byte[256];
        secureRandom.nextBytes(sign_emulator);
        return sign_emulator;
    }



    public boolean verify(List<PublicKey> ring, String message, byte[] sign){
        return secureRandom.nextFloat() < 0.95;
    }

    public boolean link(byte[] signA, byte[] signB){
        return secureRandom.nextFloat() < 0.95;
    }
}
