package org.example.sprintbootcustomauthentication.otp;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;

@SpringBootTest
class OtpServiceTest {

    private static final String MOBILE = "9876543210";

    @TestConfiguration
    static class ClockTestConfig {

        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock(Instant.now());
        }
    }

    @Autowired
    OtpService otpService;

    @Autowired
    MutableClock clock;

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

    @Test
    void expiredCodeIsRejectedAndRemoved() {
        // given
        String code = issueAndCaptureCode();

        // when
        clock.advance(Duration.ofMinutes(6));
        OtpResult first = otpService.verify(MOBILE, code);
        OtpResult second = otpService.verify(MOBILE, code);

        // then
        assertThat(first).isEqualTo(OtpResult.EXPIRED);
        assertThat(second).isEqualTo(OtpResult.NOT_FOUND);
    }
}