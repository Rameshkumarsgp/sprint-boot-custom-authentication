package org.example.sprintbootcustomauthentication.auth;

import lombok.RequiredArgsConstructor;
import shared.MobileNumberNormalizer;
import org.example.sprintbootcustomauthentication.otp.OtpResult;
import org.example.sprintbootcustomauthentication.otp.OtpService;
import org.example.sprintbootcustomauthentication.user.UserInfo;
import org.example.sprintbootcustomauthentication.user.UserService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final  OtpService otpService;
    private final UserService userService;

    public void  requestOtp(String rawMobileNumber) {
        otpService.issue(rawMobileNumber);
    }

    public AuthResult verifyOtp(String rawMobileNumber, String code) {
        String mobileNumber = MobileNumberNormalizer.normalize(rawMobileNumber);

        OtpResult otpResult = otpService.verify(mobileNumber, code);

        return switch (otpResult) {
            case TOO_MANY_ATTEMPTS -> AuthResult.of(AuthResult.Status.TOO_MANY_ATTEMPTS);
            case INVALID, EXPIRED, NOT_FOUND -> AuthResult.of(AuthResult.Status.INVALID_OTP);
            case VERIFIED -> authenticate(mobileNumber);
        };
    }

    private AuthResult authenticate(String mobileNumber) {
        UserInfo user = userService.findOrCreate(mobileNumber);
        if (!user.enabled()) {
            return AuthResult.of(AuthResult.Status.ACCOUNT_DISABLED);
        }
        return AuthResult.authenticated(user);
    }
}
