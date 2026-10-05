package org.example.sprintbootcustomauthentication.otp;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.otp.internal.Otp;
import org.example.sprintbootcustomauthentication.otp.internal.OtpGenerator;
import org.example.sprintbootcustomauthentication.otp.internal.OtpHasher;
import org.example.sprintbootcustomauthentication.otp.internal.OtpRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository repository;
    private final OtpGenerator generator;
    private final OtpHasher hasher;
    private final OtpSender sender;
    private final OtpProperties properties;

    @Transactional
    public void issue(String mobileNumber) {
        String code = generator.generate();

        Otp otp = repository.findByMobileNumberForUpdate(mobileNumber).orElseGet(Otp::new);
        otp.setMobileNumber(mobileNumber);
        otp.setOtpHash(hasher.hash(mobileNumber, code));
        otp.setExpiresAt(Instant.now().plus(properties.ttl()));
        otp.setAttempts(0);
        repository.save(otp);

        sender.send(mobileNumber, code);

    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public OtpResult verify(String mobileNumber, String code) {
        Otp otp = repository.findByMobileNumberForUpdate(mobileNumber).orElse(null);

        if (otp == null) {
            return OtpResult.NOT_FOUND;
        }

        if (Instant.now().isAfter(otp.getExpiresAt())) {
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
