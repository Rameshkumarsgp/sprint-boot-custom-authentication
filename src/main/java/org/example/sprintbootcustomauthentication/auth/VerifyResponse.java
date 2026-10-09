package org.example.sprintbootcustomauthentication.auth;

public record VerifyResponse(String tokenType, String accessToken, long expiresIn,
                             String refreshToken, Long userId) {
}
