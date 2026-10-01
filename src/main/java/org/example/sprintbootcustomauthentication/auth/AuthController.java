package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.otp.OtpResult;
import org.example.sprintbootcustomauthentication.otp.OtpService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth/otp")
@RequiredArgsConstructor
public class AuthController {

    private final OtpService otpService;

    @PostMapping("/request")
    public ResponseEntity<Map<String, String>> request(@Valid @RequestBody OtpRequest body) {
        otpService.issue(body.mobileNumber());
        return ResponseEntity.accepted().body(Map.of("message", "OTP sent"));
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(@Valid @RequestBody OtpVerifyRequest body) {
        OtpResult result = otpService.verify(body.mobileNumber(), body.otp());
        return switch (result) {
            case VERIFIED -> ResponseEntity.ok(Map.of("verified", true));
            case TOO_MANY_ATTEMPTS -> ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Too many attempts. Request a new OTP."));
            case INVALID, EXPIRED, NOT_FOUND -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid or expired OTP"));
        };
    }

    //
}
