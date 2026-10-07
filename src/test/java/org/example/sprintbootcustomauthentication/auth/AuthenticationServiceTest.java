package org.example.sprintbootcustomauthentication.auth;

import org.example.sprintbootcustomauthentication.otp.OtpResult;
import org.example.sprintbootcustomauthentication.otp.OtpService;
import org.example.sprintbootcustomauthentication.shared.MobileNumber;
import org.example.sprintbootcustomauthentication.user.UserInfo;
import org.example.sprintbootcustomauthentication.user.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    private static final MobileNumber MOBILE = new MobileNumber("919876543210");
    private static final String CODE = "483921";

    @Mock
    OtpService otpService;

    @Mock
    UserService userService;

    @InjectMocks
    AuthenticationService authenticationService;

    @Test
    void requestOtpDelegatesToOtpServiceOnly() {
        // given

        // when
        authenticationService.requestOtp(MOBILE);

        // then
        verify(otpService).issue(MOBILE);
        verifyNoInteractions(userService);
    }

    @Test
    void verifiedOtpForEnabledUserIsAuthenticated() {
        // given
        UserInfo user = new UserInfo(7L, MOBILE.value(), true);
        when(otpService.verify(MOBILE, CODE)).thenReturn(OtpResult.VERIFIED);
        when(userService.findOrCreate(MOBILE)).thenReturn(user);

        // when
        AuthResult result = authenticationService.verifyOtp(MOBILE, CODE);

        // then
        assertThat(result.status()).isEqualTo(AuthResult.Status.AUTHENTICATED);
        assertThat(result.userInfo()).isEqualTo(user);
    }

    @Test
    void verifiedOtpForDisabledUserIsRejected() {
        // given
        when(otpService.verify(MOBILE, CODE)).thenReturn(OtpResult.VERIFIED);
        when(userService.findOrCreate(MOBILE)).thenReturn(new UserInfo(7L, MOBILE.value(), false));

        // when
        AuthResult result = authenticationService.verifyOtp(MOBILE, CODE);

        // then
        assertThat(result.status()).isEqualTo(AuthResult.Status.ACCOUNT_DISABLED);
        assertThat(result.userInfo()).isNull();
    }

    @Test
    void tooManyAttemptsPassesThroughWithoutLookingUpTheUser() {
        // given
        when(otpService.verify(MOBILE, CODE)).thenReturn(OtpResult.TOO_MANY_ATTEMPTS);

        // when
        AuthResult result = authenticationService.verifyOtp(MOBILE, CODE);

        // then
        assertThat(result.status()).isEqualTo(AuthResult.Status.TOO_MANY_ATTEMPTS);
        verifyNoInteractions(userService);
    }

    @ParameterizedTest
    @EnumSource(value = OtpResult.class, names = {"INVALID", "EXPIRED", "NOT_FOUND"})
    void failedOtpsAllBecomeInvalidOtpWithoutLookingUpTheUser(OtpResult outcome) {
        // given
        when(otpService.verify(MOBILE, CODE)).thenReturn(outcome);

        // when
        AuthResult result = authenticationService.verifyOtp(MOBILE, CODE);

        // then
        assertThat(result.status()).isEqualTo(AuthResult.Status.INVALID_OTP);
        assertThat(result.userInfo()).isNull();
        verifyNoInteractions(userService);
    }
}
