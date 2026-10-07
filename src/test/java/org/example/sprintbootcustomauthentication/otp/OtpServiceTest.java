package org.example.sprintbootcustomauthentication.otp;

import org.example.sprintbootcustomauthentication.otp.internal.Otp;
import org.example.sprintbootcustomauthentication.otp.internal.OtpGenerator;
import org.example.sprintbootcustomauthentication.otp.internal.OtpHasher;
import org.example.sprintbootcustomauthentication.otp.internal.OtpRepository;
import shared.MobileNumber;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    private static final MobileNumber MOBILE = new MobileNumber("919876543210");
    private static final String NUMBER = MOBILE.value();
    private static final String CODE = "483921";

    @Mock
    OtpRepository repository;

    @Mock
    OtpGenerator generator;

    @Mock
    OtpSender sender;

    private final OtpProperties properties = new OtpProperties(6, Duration.ofMinutes(5), 5, "test-secret");
    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private final AtomicReference<Otp> stored = new AtomicReference<>();

    private OtpHasher hasher;
    private OtpService otpService;

    @BeforeEach
    void setUp() {
        hasher = new OtpHasher(properties);
        otpService = new OtpService(repository, generator, hasher, sender, properties, clock);

        lenient().when(generator.generate()).thenReturn(CODE);
        lenient().when(repository.findByMobileNumberForUpdate(NUMBER))
                .thenAnswer(invocation -> Optional.ofNullable(stored.get()));
        lenient().doAnswer(invocation -> {
            Otp otp = new Otp();
            otp.setMobileNumber(invocation.getArgument(0));
            otp.setOtpHash(invocation.getArgument(1));
            otp.setExpiresAt(invocation.getArgument(2));
            otp.setAttempts(0);
            stored.set(otp);
            return null;
        }).when(repository).upsert(any(), any(), any());
        lenient().doAnswer(invocation -> {
            stored.set(null);
            return null;
        }).when(repository).delete(any(Otp.class));
    }

    @Test
    void issueStoresHashedCodeAndSendsPlainCode() {
        // given

        // when
        otpService.issue(MOBILE);

        // then
        verify(sender).send(NUMBER, CODE);
        Otp otp = stored.get();
        assertThat(otp.getOtpHash()).isEqualTo(hasher.hash(NUMBER, CODE)).isNotEqualTo(CODE);
        assertThat(otp.getExpiresAt()).isEqualTo(clock.instant().plus(Duration.ofMinutes(5)));
        assertThat(otp.getAttempts()).isZero();
    }

    @Test
    void issuingAgainReplacesTheOldOtp() {
        // given
        otpService.issue(MOBILE);
        otpService.verify(MOBILE, "000000");

        // when
        when(generator.generate()).thenReturn("222222");
        otpService.issue(MOBILE);

        // then
        assertThat(stored.get().getAttempts()).isZero();
        assertThat(otpService.verify(MOBILE, CODE)).isEqualTo(OtpResult.INVALID);
        assertThat(otpService.verify(MOBILE, "222222")).isEqualTo(OtpResult.VERIFIED);
    }

    @Test
    void correctCodeVerifiesOnlyOnce() {
        // given
        otpService.issue(MOBILE);

        // when
        OtpResult first = otpService.verify(MOBILE, CODE);
        OtpResult second = otpService.verify(MOBILE, CODE);

        // then
        assertThat(first).isEqualTo(OtpResult.VERIFIED);
        assertThat(second).isEqualTo(OtpResult.NOT_FOUND);
    }

    @Test
    void wrongCodeIsInvalidAndCountsAnAttempt() {
        // given
        otpService.issue(MOBILE);

        // when
        OtpResult result = otpService.verify(MOBILE, "000000");

        // then
        assertThat(result).isEqualTo(OtpResult.INVALID);
        assertThat(stored.get().getAttempts()).isEqualTo(1);
    }

    @Test
    void lockedAfterTooManyAttempts() {
        // given
        otpService.issue(MOBILE);

        // when
        for (int i = 0; i < 5; i++) {
            otpService.verify(MOBILE, "000000");
        }
        OtpResult result = otpService.verify(MOBILE, CODE);

        // then
        assertThat(result).isEqualTo(OtpResult.TOO_MANY_ATTEMPTS);
    }

    @Test
    void expiredCodeIsRejectedAndRemoved() {
        // given
        otpService.issue(MOBILE);

        // when
        clock.advance(Duration.ofMinutes(6));
        OtpResult first = otpService.verify(MOBILE, CODE);
        OtpResult second = otpService.verify(MOBILE, CODE);

        // then
        assertThat(first).isEqualTo(OtpResult.EXPIRED);
        assertThat(second).isEqualTo(OtpResult.NOT_FOUND);
    }

    @Test
    void unknownMobileIsNotFound() {
        // given

        // when
        OtpResult result = otpService.verify(MOBILE, CODE);

        // then
        assertThat(result).isEqualTo(OtpResult.NOT_FOUND);
    }
}