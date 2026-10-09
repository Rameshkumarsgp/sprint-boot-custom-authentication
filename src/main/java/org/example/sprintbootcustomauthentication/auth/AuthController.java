package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.token.TokenPair;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.example.sprintbootcustomauthentication.shared.MobileNumber;

import java.util.Map;

@RestController
@RequestMapping("/auth/otp")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/request")
    public ResponseEntity<Map<String, String>> request(@Valid @RequestBody OtpRequest body) {
        authenticationService.requestOtp(MobileNumber.of(body.mobileNumber()));
        return ResponseEntity.accepted().body(Map.of("message", "OTP sent"));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@Valid @RequestBody OtpVerifyRequest body) {
        AuthResult result =
                authenticationService.verifyOtp(MobileNumber.of(body.mobileNumber()), body.otp());
        return switch (result.status()) {
            case AUTHENTICATED -> ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .body(toResponse(result));
            case TOO_MANY_ATTEMPTS -> ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiError.of("TOO_MANY_ATTEMPTS"));
            case INVALID_OTP -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiError.of("INVALID_OR_EXPIRED_OTP"));
            case ACCOUNT_DISABLED -> ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiError.of("ACCOUNT_DISABLED"));
        };
    }

    private VerifyResponse toResponse(AuthResult result) {
        TokenPair tokens = result.tokens();
        return new VerifyResponse(
                "Bearer",
                tokens.accessToken().value(),
                tokens.expiresInSeconds(),
                tokens.refreshToken().value(),
                result.userInfo().id());
    }
}
