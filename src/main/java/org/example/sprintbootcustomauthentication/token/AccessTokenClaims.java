package org.example.sprintbootcustomauthentication.token;

import java.time.Instant;
import java.util.Set;

public record AccessTokenClaims(Long userId, String tokenId, Instant expiresAt,
                                Set<String> roles, Set<String> permissions) {

    public AccessTokenClaims(Long userId, String tokenId, Instant expiresAt) {
        this(userId, tokenId, expiresAt, Set.of(), Set.of());
    }
}
