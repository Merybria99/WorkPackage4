package it.unisa.aps.contract;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents a smart contract abstraction
 */
public class Contract implements Serializable {
    private byte[] contractId;
    private int vote;
    private Timestamp lastModified;
    private byte[] lastCommit;
    private List<Contract> transaction;

    /**
     *
     * @param contractId   represents the sign produced by the client for the
     *                     contract creation request
     * @param vote         represents the vote
     * @param lastModified represents the timestamp of the last change made
     * @param lastCommit   represents the last sign
     */
    public Contract(byte[] contractId, int vote, Timestamp lastModified, byte[] lastCommit) {
        this.contractId = contractId;
        this.vote = vote;
        this.lastModified = lastModified;
        this.lastCommit = lastCommit;
        transaction = new ArrayList<>();
    }

    /**
     * Overload of the previous constructor method.
     * In this case, lastCommit is null
     * @param contractId
     * @param vote
     * @param lastModified
     */
    public Contract(byte[] contractId, int vote, Timestamp lastModified) {
        this.contractId = contractId;
        this.vote = vote;
        this.lastModified = lastModified;
        lastCommit = null;
        transaction = new ArrayList<>();
    }

    /**
     * @return byte[] represents the contract ID
     */
    public byte[] getContractId() {
        return contractId;
    }

    /**
     * @return byte[] represents the last sign
     */
    public byte[] getLastCommit() {
        return lastCommit;
    }

    /**
     * @return int represents the vote
     */
    public int getVote() {
        return vote;
    }

    /**
     * @return Timestamp represents the last modify operation timestamp
     */
    public Timestamp getLastModified() {
        return lastModified;
    }

    /**
     * @return List<Contract> represents the list of all the previous state of the
     *         contract
     */
    public List<Contract> getTransaction() {
        return transaction;
    }

    /**
     * This method updates the contract, so it changes all the fields and inserts
     * the previous state of this contract into transaction list
     *
     * @param vote         represents new vote
     * @param lastModified represents the current timestamp
     * @param lastCommit   represents the last sign of the client during the modify
     *                     operation
     */
    public void update(int vote, Timestamp lastModified, byte[] lastCommit) {
        Contract contract = new Contract(this.contractId, this.vote, this.lastModified, this.lastCommit);
        this.vote = vote;
        this.lastModified = lastModified;
        this.lastCommit = lastCommit;
        addTransaction(contract);
    }

    /**
     * This method adds a new smart contract, which is defined entirely by the parameter transaction,
     * into a list of contract.
     *
     * @param transaction represents a single smart contract
     */
    private void addTransaction(Contract transaction) {
        this.transaction.add(transaction);
    }

    /**
     * @return String represents the formatted string of the contract
     */
    @Override
    public String toString() {
        return vote + " submitted on  " + lastModified;
    }
}
