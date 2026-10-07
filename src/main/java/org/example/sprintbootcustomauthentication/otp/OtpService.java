package org.example.sprintbootcustomauthentication.otp;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.otp.internal.Otp;
import org.example.sprintbootcustomauthentication.otp.internal.OtpGenerator;
import org.example.sprintbootcustomauthentication.otp.internal.OtpHasher;
import org.example.sprintbootcustomauthentication.otp.internal.OtpRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.example.sprintbootcustomauthentication.shared.MobileNumber;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository repository;
    private final OtpGenerator generator;
    private final OtpHasher hasher;
    private final OtpSender sender;
    private final OtpProperties properties;
    private final Clock clock;

    @Transactional
    public void issue(MobileNumber mobileNumber) {
        String number = mobileNumber.value();
        String code = generator.generate();

        repository.upsert(
                number,
                hasher.hash(number, code),
                Instant.now(clock).plus(properties.ttl()));

        sender.send(number, code);

    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public OtpResult verify(MobileNumber mobileNumber, String code) {
        String number = mobileNumber.value();
        Otp otp = repository.findByMobileNumberForUpdate(number).orElse(null);

        if (otp == null) {
            return OtpResult.NOT_FOUND;
        }

        if (Instant.now(clock).isAfter(otp.getExpiresAt())) {
            repository.delete(otp);
            return OtpResult.EXPIRED;
        }

        if (otp.getAttempts() >= properties.maxAttempts()) {
            return OtpResult.TOO_MANY_ATTEMPTS;
        }

        if (hasher.matches(number, code, otp.getOtpHash())) {
            repository.delete(otp);
            return OtpResult.VERIFIED;
        }

        otp.setAttempts(otp.getAttempts() + 1);
        return OtpResult.INVALID;
    }
}
