$version: "2"

namespace example.auth

use aws.protocols#restJson1

/// Mobile number + one-time password authentication API.
///
/// Login is a two-step flow: request an OTP, then verify it to receive an access token
/// (a short-lived JWT) and a refresh token (opaque, single use, rotated on every refresh).
@restJson1
@httpBearerAuth
@title("Custom Authentication API")
service AuthService {
    version: "2026-10-09"
    operations: [
        RequestOtp
        VerifyOtp
        RefreshToken
        Logout
        GetMe
    ]
}

/// Sends a one-time password to the given mobile number. Always answers 202 for a
/// well-formed number, whether or not the number is known.
@auth([])
@http(method: "POST", uri: "/auth/otp/request", code: 202)
operation RequestOtp {
    input := {
        /// Mobile number in any common format; it is normalized to country-code digits.
        @required
        @pattern("^[+0-9()\\-\\s]{10,20}$")
        mobileNumber: String
    }

    output := {
        @required
        message: String
    }

    errors: [
        ValidationFailed
    ]
}

/// Verifies the OTP. On success the caller is authenticated and receives tokens.
/// Wrong, expired and unknown OTPs are indistinguishable (401).
@auth([])
@http(method: "POST", uri: "/auth/otp/verify", code: 200)
operation VerifyOtp {
    input := {
        @required
        @pattern("^[+0-9()\\-\\s]{10,20}$")
        mobileNumber: String

        @required
        @pattern("^\\d{6}$")
        otp: String
    }

    output := with [TokenFields] {}

    errors: [
        ValidationFailed
        Unauthorized
        Forbidden
        TooManyRequests
    ]
}

/// Exchanges a refresh token for a new access token and a new refresh token.
/// The presented refresh token is consumed; presenting a consumed token again revokes
/// the whole session (token family).
@auth([])
@http(method: "POST", uri: "/auth/token/refresh", code: 200)
operation RefreshToken {
    input := {
        @required
        @length(min: 1, max: 200)
        refreshToken: String
    }

    output := with [TokenFields] {}

    errors: [
        ValidationFailed
        Unauthorized
        Forbidden
    ]
}

/// Revokes the session that the refresh token belongs to. Always answers 204.
@auth([])
@http(method: "POST", uri: "/auth/logout", code: 204)
operation Logout {
    input := {
        @required
        @length(min: 1, max: 200)
        refreshToken: String
    }

    errors: [
        ValidationFailed
    ]
}

/// Returns the caller as seen from the access token.
@readonly
@http(method: "GET", uri: "/me", code: 200)
operation GetMe {
    output := {
        @required
        userId: Long

        @required
        tokenId: String

        @required
        @timestampFormat("date-time")
        expiresAt: Timestamp
    }

    errors: [
        Unauthorized
    ]
}

@mixin
structure TokenFields {
    /// Always "Bearer".
    @required
    tokenType: String

    /// Short-lived signed JWT (15 minutes by default).
    @required
    accessToken: String

    /// Lifetime of the access token in seconds.
    @required
    expiresIn: Long

    /// Opaque single-use token (30 days by default).
    @required
    refreshToken: String

    @required
    userId: Long
}

@mixin
structure ApiErrorFields {
    /// Machine-readable error code, for example VALIDATION_FAILED.
    @required
    error: String

    details: ErrorDetails
}

map ErrorDetails {
    key: String
    value: String
}

@error("client")
@httpError(400)
structure ValidationFailed with [ApiErrorFields] {}

@error("client")
@httpError(401)
structure Unauthorized with [ApiErrorFields] {}

@error("client")
@httpError(403)
structure Forbidden with [ApiErrorFields] {}

@error("client")
@httpError(429)
structure TooManyRequests with [ApiErrorFields] {}
