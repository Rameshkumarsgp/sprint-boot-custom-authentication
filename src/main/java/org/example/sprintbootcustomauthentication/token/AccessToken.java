package org.example.sprintbootcustomauthentication.token;

import java.time.Instant;

public record AccessToken(String value, Instant expiresAt) {
}
