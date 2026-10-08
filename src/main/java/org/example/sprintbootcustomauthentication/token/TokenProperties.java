package org.example.sprintbootcustomauthentication.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.jwt")
public record TokenProperties(String secret, String issuer, String audience, Duration accessTtl,
                              Duration refreshTtl) {
}
