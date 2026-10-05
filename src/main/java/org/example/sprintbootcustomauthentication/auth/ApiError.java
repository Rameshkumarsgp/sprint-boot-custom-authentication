package org.example.sprintbootcustomauthentication.auth;

import java.util.Map;

public record ApiError(String error, Map<String, String> details) {

    public static ApiError of(String error) {
        return new ApiError(error, Map.of());
    }
}