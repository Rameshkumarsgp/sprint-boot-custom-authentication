package org.example.sprintbootcustomauthentication.token;

import java.time.Instant;

public record IssuedRefreshToken(String value, Instant expiresAt) {
}
