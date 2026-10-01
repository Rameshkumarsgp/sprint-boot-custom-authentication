package org.example.sprintbootcustomauthentication.otp.internal;

import org.example.sprintbootcustomauthentication.otp.OtpProperties;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class OtpGenerator {
    private final SecureRandom random = new SecureRandom();
    private  final OtpProperties properties;

    OtpGenerator(OtpProperties properties) {
        this.properties = properties;
    }

    public String generate() {
        int length = properties.length();
        StringBuilder otp = new StringBuilder(length);
        for (int i= 0; i< length ; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

}
