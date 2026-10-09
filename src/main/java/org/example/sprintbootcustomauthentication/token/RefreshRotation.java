package org.example.sprintbootcustomauthentication.token;

public record RefreshRotation(Status status, Long userId, IssuedRefreshToken token) {

    public enum Status {
        ROTATED,
        INVALID
    }

    static RefreshRotation rotated(Long userId, IssuedRefreshToken token) {
        return new RefreshRotation(Status.ROTATED, userId, token);
    }

    static RefreshRotation invalid() {
        return new RefreshRotation(Status.INVALID, null, null);
    }
}
