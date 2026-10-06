package org.example.sprintbootcustomauthentication.otp;

public class InvalidMobileNumberException extends RuntimeException {
    public InvalidMobileNumberException() {
        super("Invalid mobile number");
    }
}
