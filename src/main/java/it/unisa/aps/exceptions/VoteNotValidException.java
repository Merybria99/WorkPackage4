package it.unisa.aps.exceptions;

public class VoteNotValidException extends RuntimeException{
    public VoteNotValidException() {
    }

    public VoteNotValidException(String message) {
        super(message);
    }
}
