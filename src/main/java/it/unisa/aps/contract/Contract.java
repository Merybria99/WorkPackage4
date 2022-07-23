package it.unisa.aps.contract;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

public class Contract  implements Serializable {
    private byte[] contractId;
    private int vote;
    private Timestamp lastModified;
    private byte[] sign;
    private List<Contract> transaction;

    public Contract(byte[] contractId, int vote, Timestamp lastModified, byte[] sign) {
        this.contractId = contractId;
        this.vote = vote;
        this.lastModified = lastModified;
        this.sign = sign;
        transaction = new ArrayList<>();
    }

    public Contract(byte[] contractId, int vote, Timestamp lastModified) {
        this.contractId = contractId;
        this.vote = vote;
        this.lastModified = lastModified;
        sign = null;
        transaction = new ArrayList<>();
    }

    public byte[] getContractId() {
        return contractId;
    }

    public byte[] getSign() {
        return sign;
    }

    public int getVote() {
        return vote;
    }

    public Timestamp getLastModified() {
        return lastModified;
    }

    public List<Contract> getTransaction() {
        return transaction;
    }

    public void update( int vote, Timestamp lastModified, byte[] sign){
        Contract contract = new Contract(this.contractId,this.vote, this.lastModified,this.sign);
        this.vote=vote;
        this.lastModified=lastModified;
        this.sign=sign;
        addTransaction(contract);
    }

    private void addTransaction(Contract transaction) {
        this.transaction.add(transaction);
    }

    @Override
    public String toString() {
       return vote +" submitted on  "+lastModified;
    }
}
