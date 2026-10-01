package org.example.sprintbootcustomauthentication.otp;

public interface OtpSender {
    void send(String mobileNumber, String otp);
}
