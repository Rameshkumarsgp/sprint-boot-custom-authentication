package org.example.sprintbootcustomauthentication.token;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException() {
        super("Invalid token");
    }
}
