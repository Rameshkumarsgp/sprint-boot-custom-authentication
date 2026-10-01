package org.example.sprintbootcustomauthentication.otp;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.otp")
public record OtpProperties(int length, Duration ttl, int maxAttempts, String secret) {

}
