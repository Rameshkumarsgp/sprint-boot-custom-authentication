package org.example.sprintbootcustomauthentication.auth;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.otp.OtpResult;
import org.example.sprintbootcustomauthentication.otp.OtpService;
import org.example.sprintbootcustomauthentication.token.RefreshRotation;
import org.example.sprintbootcustomauthentication.token.TokenPair;
import org.example.sprintbootcustomauthentication.token.TokenService;
import org.example.sprintbootcustomauthentication.user.UserInfo;
import org.example.sprintbootcustomauthentication.user.UserService;
import org.springframework.stereotype.Service;
import org.example.sprintbootcustomauthentication.shared.MobileNumber;
import org.example.sprintbootcustomauthentication.shared.UserAuthorities;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final OtpService otpService;
    private final UserService userService;
    private final TokenService tokenService;

    public void requestOtp(MobileNumber mobileNumber) {
        otpService.issue(mobileNumber);
    }

    public AuthResult verifyOtp(MobileNumber mobileNumber, String code) {
        OtpResult otpResult = otpService.verify(mobileNumber, code);

        return switch (otpResult) {
            case TOO_MANY_ATTEMPTS -> AuthResult.of(AuthResult.Status.TOO_MANY_ATTEMPTS);
            case INVALID, EXPIRED, NOT_FOUND -> AuthResult.of(AuthResult.Status.INVALID_OTP);
            case VERIFIED -> authenticate(mobileNumber);
        };
    }

    public AuthResult refresh(String rawRefreshToken) {
        RefreshRotation rotation = tokenService.rotateRefreshToken(rawRefreshToken);
        if (rotation.status() != RefreshRotation.Status.ROTATED) {
            return AuthResult.of(AuthResult.Status.INVALID_REFRESH_TOKEN);
        }

        UserInfo user = userService.findById(rotation.userId()).orElse(null);
        if (user == null) {
            tokenService.revokeAllFor(rotation.userId());
            return AuthResult.of(AuthResult.Status.INVALID_REFRESH_TOKEN);
        }
        if (!user.enabled()) {
            tokenService.revokeAllFor(user.id());
            return AuthResult.of(AuthResult.Status.ACCOUNT_DISABLED);
        }

        UserAuthorities authorities = userService.authoritiesFor(user.id());
        return AuthResult.authenticated(user, tokenService.pairFor(user.id(), authorities, rotation.token()));
    }

    public void logout(String rawRefreshToken) {
        tokenService.logout(rawRefreshToken);
    }

    private AuthResult authenticate(MobileNumber mobileNumber) {
        UserInfo user = userService.findOrCreate(mobileNumber);
        if (!user.enabled()) {
            return AuthResult.of(AuthResult.Status.ACCOUNT_DISABLED);
        }
        UserAuthorities authorities = userService.authoritiesFor(user.id());
        TokenPair tokens = tokenService.issueFor(user.id(), authorities);
        return AuthResult.authenticated(user, tokens);
    }
}
