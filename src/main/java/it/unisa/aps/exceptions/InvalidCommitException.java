package it.unisa.aps.exceptions;

public class InvalidCommitException extends RuntimeException {
    public InvalidCommitException() {
    }

    public InvalidCommitException(String message) {
        super(message);
    }
}
