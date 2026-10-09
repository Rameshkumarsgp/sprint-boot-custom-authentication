package org.example.sprintbootcustomauthentication.security;

import java.time.Instant;

public record AuthenticatedUser(Long userId, String tokenId, Instant expiresAt) {
}
