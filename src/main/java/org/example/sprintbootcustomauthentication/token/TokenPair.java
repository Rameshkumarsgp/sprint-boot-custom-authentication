package org.example.sprintbootcustomauthentication.token;

public record TokenPair(AccessToken accessToken, IssuedRefreshToken refreshToken, long expiresInSeconds) {
}
