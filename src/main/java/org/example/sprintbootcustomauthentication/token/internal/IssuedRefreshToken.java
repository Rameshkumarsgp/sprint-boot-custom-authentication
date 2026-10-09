package org.example.sprintbootcustomauthentication.token.internal;

import java.time.Instant;

public record IssuedRefreshToken(String value, Instant expiresAt) {

}
