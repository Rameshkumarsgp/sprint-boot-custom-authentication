package org.example.sprintbootcustomauthentication.auth;

import org.example.sprintbootcustomauthentication.token.TokenPair;
import org.example.sprintbootcustomauthentication.user.UserInfo;

public record AuthResult(Status status, UserInfo userInfo, TokenPair tokens) {
    //
    public enum Status {
        AUTHENTICATED,
        INVALID_OTP,
        TOO_MANY_ATTEMPTS,
        ACCOUNT_DISABLED
    }

    static AuthResult authenticated(UserInfo userInfo, TokenPair tokens) {
        return new AuthResult(Status.AUTHENTICATED, userInfo, tokens);
    }

    static AuthResult of(Status status) {
        return new AuthResult(status, null, null);
    }

    //
}
