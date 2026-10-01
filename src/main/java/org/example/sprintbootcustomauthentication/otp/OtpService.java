package org.example.sprintbootcustomauthentication.otp;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.otp.internal.Otp;
import org.example.sprintbootcustomauthentication.otp.internal.OtpGenerator;
import org.example.sprintbootcustomauthentication.otp.internal.OtpHasher;
import org.example.sprintbootcustomauthentication.otp.internal.OtpRepository;
import org.springframework.stereotype.Service;

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

        Otp otp = repository.findByMobileNumber(mobileNumber).orElseGet(Otp::new);
        otp.setMobileNumber(mobileNumber);
        otp.setOtpHash(hasher.hash(mobileNumber, code));
        otp.setExpiresAt(Instant.now().plus(properties.ttl()));
        otp.setAttempts(0);
        repository.save(otp);

        sender.send(mobileNumber, code);

    }

    @Transactional
    public OtpResult verify(String mobileNumber, String code) {
        //
        Otp otp = repository.findByMobileNumber(mobileNumber).orElse(null);

        if (otp == null) {
            return OtpResult.NOT_FOUND;
        }

        if (Instant.now().isAfter(otp.getExpiresAt())) {
            return OtpResult.EXPIRED;
        }

        if (otp.getAttempts() >= properties.maxAttempts()) {
            return OtpResult.TOO_MANY_ATTEMPTS;
        }

        if (hasher.matches(mobileNumber, code, otp.getOtpHash())) {
            repository.delete(otp);
        }

        otp.setAttempts(otp.getAttempts() + 1);
        repository.save(otp);
        return OtpResult.INVALID;
    }
}
