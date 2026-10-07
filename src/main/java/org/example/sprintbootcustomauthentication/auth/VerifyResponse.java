package org.example.sprintbootcustomauthentication.auth;

public record VerifyResponse(boolean verified, Long userId) {
}
