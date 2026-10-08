package org.example.sprintbootcustomauthentication.token;

import java.time.Instant;

public record AccessTokenClaims(Long userId, String tokenId, Instant expiresAt) {
}
