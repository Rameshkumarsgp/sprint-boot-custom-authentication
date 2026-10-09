package org.example.sprintbootcustomauthentication.token;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.token.internal.RefreshToken;
import org.example.sprintbootcustomauthentication.token.internal.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final int TOKEN_BYTES = 32;

    private final RefreshTokenRepository repository;
    private final TokenProperties properties;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @Transactional
    public IssuedRefreshToken issue(Long userId) {
        return issue(userId, UUID.randomUUID().toString());
    }

    IssuedRefreshToken issue(Long userId, String familyId) {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        Instant now = clock.instant();
        RefreshToken entity = new RefreshToken();
        entity.setUserId(userId);
        entity.setTokenHash(hash(rawToken));
        entity.setFamilyId(familyId);
        entity.setCreatedAt(now);
        entity.setExpiresAt(now.plus(properties.refreshTtl()));
        repository.save(entity);

        return new IssuedRefreshToken(rawToken, entity.getExpiresAt());
    }

    static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    //
}
