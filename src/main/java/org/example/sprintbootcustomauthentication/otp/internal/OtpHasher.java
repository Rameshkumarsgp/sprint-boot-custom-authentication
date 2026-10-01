package org.example.sprintbootcustomauthentication.otp.internal;

import org.example.sprintbootcustomauthentication.otp.OtpProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;

@Component
public class OtpHasher {
    public static final String ALGORITHM = "HmacSHA256";
    private final SecretKeySpec key;

    OtpHasher(OtpProperties properties) {
        this.key =
                new SecretKeySpec(properties.secret().getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public  String hash(String mobileNumber, String otp) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            byte[] digest =
                    mac.doFinal((mobileNumber + ":" + otp).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not compute OTP hash", e);
        }
    }

    public  boolean matches(String mobileNumber, String otp, String storedHash) {
        byte[] expected = hash(mobileNumber, otp).getBytes(StandardCharsets.UTF_8);
        byte[] actual = storedHash.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }
}
