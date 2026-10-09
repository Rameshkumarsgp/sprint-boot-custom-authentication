package org.example.sprintbootcustomauthentication.auth;

import org.example.sprintbootcustomauthentication.token.TokenPair;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

final class AuthResponses {

    private AuthResponses() {
    }

    static ResponseEntity<?> from(AuthResult result) {
        return switch (result.status()) {
            case AUTHENTICATED -> ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .body(toBody(result));
            case TOO_MANY_ATTEMPTS -> ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiError.of("TOO_MANY_ATTEMPTS"));
            case INVALID_OTP -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiError.of("INVALID_OR_EXPIRED_OTP"));
            case INVALID_REFRESH_TOKEN -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiError.of("INVALID_REFRESH_TOKEN"));
            case ACCOUNT_DISABLED -> ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiError.of("ACCOUNT_DISABLED"));
        };
    }

    private static VerifyResponse toBody(AuthResult result) {
        TokenPair tokens = result.tokens();
        return new VerifyResponse(
                "Bearer",
                tokens.accessToken().value(),
                tokens.expiresInSeconds(),
                tokens.refreshToken().value(),
                result.userInfo().id());
    }
}
