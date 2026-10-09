package org.example.sprintbootcustomauthentication.token;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.sprintbootcustomauthentication.token.internal.RefreshToken;
import org.example.sprintbootcustomauthentication.token.internal.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
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

@Slf4j
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

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public RefreshRotation rotate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return RefreshRotation.invalid();
        }

        RefreshToken token = repository.findByTokenHashForUpdate(hash(rawToken)).orElse(null);
        if (token == null) {
            return RefreshRotation.invalid();
        }

        Instant now = clock.instant();

        if (token.getRevokedAt() != null) {
            repository.revokeFamily(token.getFamilyId(), now);
            log.warn("Refresh token reuse detected: userId={}, familyId={}",
                    token.getUserId(), token.getFamilyId());
            return RefreshRotation.invalid();
        }

        if (!now.isBefore(token.getExpiresAt())) {
            return RefreshRotation.invalid();
        }

        token.setRevokedAt(now);
        IssuedRefreshToken next = issue(token.getUserId(), token.getFamilyId());
        return RefreshRotation.rotated(token.getUserId(), next);
    }

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        repository.findByTokenHash(hash(rawToken))
                .ifPresent(token -> repository.revokeFamily(token.getFamilyId(), clock.instant()));
    }

    @Transactional
    public void revokeAllFor(Long userId) {
        repository.revokeAllForUser(userId, clock.instant());
    }
}
