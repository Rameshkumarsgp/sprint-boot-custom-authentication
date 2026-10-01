package org.example.sprintbootcustomauthentication.otp;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;

@SpringBootTest
class OtpServiceTest {

    private static final String MOBILE = "9876543210";

    @Autowired
    OtpService otpService;

    @MockitoBean
    OtpSender sender;

    private String issueAndCaptureCode() {
        otpService.issue(MOBILE);
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(sender, atLeastOnce()).send(eq(MOBILE), code.capture());
        return code.getValue();
    }

    @Test
    void correctCodeVerifiesOnlyOnce() {
        // given
        String code = issueAndCaptureCode();

        // when
        OtpResult first = otpService.verify(MOBILE, code);
        OtpResult second = otpService.verify(MOBILE, code);

        // then
        assertThat(first).isEqualTo(OtpResult.VERIFIED);
        assertThat(second).isEqualTo(OtpResult.NOT_FOUND);
    }

    @Test
    void wrongCodeIsInvalid() {
        // given
        issueAndCaptureCode();

        // when
        OtpResult result = otpService.verify(MOBILE, "000000");

        // then
        assertThat(result).isEqualTo(OtpResult.INVALID);
    }

    @Test
    void lockedAfterTooManyAttempts() {
        // given
        String code = issueAndCaptureCode();

        // when
        for (int i = 0; i < 5; i++) {
            otpService.verify(MOBILE, "000000");
        }
        OtpResult result = otpService.verify(MOBILE, code);

        // then
        assertThat(result).isEqualTo(OtpResult.TOO_MANY_ATTEMPTS);
    }
}