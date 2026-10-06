package org.example.sprintbootcustomauthentication.otp;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.otp.internal.Otp;
import org.example.sprintbootcustomauthentication.otp.internal.OtpGenerator;
import org.example.sprintbootcustomauthentication.otp.internal.OtpHasher;
import org.example.sprintbootcustomauthentication.otp.internal.OtpRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

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
    public void issue(String rawMobileNumber) {
        String mobileNumber = MobileNumberNormalizer.normalize(rawMobileNumber);
        String code = generator.generate();

        repository.upsert(
                mobileNumber,
                hasher.hash(mobileNumber, code),
                Instant.now(clock).plus(properties.ttl()));

        sender.send(mobileNumber, code);

    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public OtpResult verify(String rawMobileNumber, String code) {
        String mobileNumber = MobileNumberNormalizer.normalize(rawMobileNumber);
        Otp otp = repository.findByMobileNumberForUpdate(mobileNumber).orElse(null);

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

        if (hasher.matches(mobileNumber, code, otp.getOtpHash())) {
            repository.delete(otp);
            return OtpResult.VERIFIED;
        }

        otp.setAttempts(otp.getAttempts() + 1);
        return OtpResult.INVALID;
    }
}
