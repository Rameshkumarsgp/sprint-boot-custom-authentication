package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.shared.MobileNumber;
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
        return AuthResponses.from(result);
    }
}
