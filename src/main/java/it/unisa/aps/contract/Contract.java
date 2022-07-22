package it.unisa.aps.contract;
import java.io.Serializable;
import java.sql.Timestamp;

public class Contract  implements Serializable {
    private byte[] contractId;
    private int vote;
    private Timestamp lastModified;
    private byte[] sign;

    public Contract(byte[] contractId, int vote, Timestamp lastModified, byte[] sign) {
        this.contractId = contractId;
        this.vote = vote;
        this.lastModified = lastModified;
        this.sign = sign;
    }

    public Contract(byte[] contractId, int vote, Timestamp lastModified) {
        this.contractId = contractId;
        this.vote = vote;
        this.lastModified = lastModified;
        sign = null;
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


    @Override
    public String toString() {
       return vote +" submitted on  "+lastModified;
    }
}
