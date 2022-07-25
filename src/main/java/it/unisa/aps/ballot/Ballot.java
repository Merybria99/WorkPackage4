package it.unisa.aps.ballot;

import it.unisa.aps.contract.Contract;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class Ballot {

    /**
     * This main run the ballot operation
     *
     * @param args represents the first and second candidates name
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        int result = getResults("./src/main/resources/VoteChain.txt");
        // the two candidates are passed by args remembering that the older should be
        // first
        System.out.println("The winner is: " + (result < 0 ? args[0] : args[1]));
    }

    /**
     * This method reads the vote for each smart contract and adds it up.
     * Once the calculation is complete, it returns the result.
     *
     * @param VoteChainPath represents the path of VoteChain file
     * @return int represents the sum of all the votes on the VoteChain
     * @throws IOException
     */
    private static int getResults(String VoteChainPath) throws IOException {
        int result = 0;

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(VoteChainPath));
        Contract readContract = null;
        try {
            while ((readContract = (Contract) ois.readObject()) != null) {
                result += readContract.getVote();
            }
        } catch (ClassNotFoundException | EOFException e) {
        }
        return result;
    }
}
