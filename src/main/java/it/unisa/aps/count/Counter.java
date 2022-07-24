package it.unisa.aps.count;

import it.unisa.aps.contract.Contract;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.Array;

public class Counter {
    public static void main(String[] args) throws Exception {

        int result = getResults("./src/main/resources/VoteChain.txt");
        // i due  candidati sono passati a linea di comando ricordando che il piu grande debba essere il primo
        System.out.println("The winner is: "+ (result<0?args[0]:args[1]));
    }

    private static int getResults(String VoteChainPath) throws IOException {
        int result = 0;

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(VoteChainPath));
        Contract readContract = null;
        try {
            while ((readContract = (Contract) ois.readObject()) != null) {
                result += readContract.getVote();
            }
        } catch (ClassNotFoundException| EOFException e) {
        }
        return result;
    }
}
