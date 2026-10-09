package org.example.sprintbootcustomauthentication.token;

import org.example.sprintbootcustomauthentication.token.internal.RefreshToken;
import org.example.sprintbootcustomauthentication.token.internal.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    @Mock
    RefreshTokenRepository repository;

    private RefreshTokenService service;

    @BeforeEach
    void setUp() {
        TokenProperties properties = new TokenProperties(
                "unit-test-secret-unit-test-secret-0123", "auth-service", "auth-service-api",
                Duration.ofMinutes(15), Duration.ofDays(30));
        service = new RefreshTokenService(repository, properties, Clock.fixed(T0, ZoneOffset.UTC));
        lenient().when(repository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private List<RefreshToken> savedTokens(int expectedCount) {
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository, times(expectedCount)).save(captor.capture());
        return captor.getAllValues();
    }

    @Test
    void storesOnlyTheHashNeverTheRawToken() {
        // given

        // when
        IssuedRefreshToken issued = service.issue(42L);

        // then
        RefreshToken saved = savedTokens(1).getFirst();
        assertThat(saved.getTokenHash())
                .isEqualTo(RefreshTokenService.hash(issued.value()))
                .isNotEqualTo(issued.value())
                .hasSize(64);
    }

    @Test
    void tokenIsLongAndUrlSafe() {
        // given

        // when
        IssuedRefreshToken issued = service.issue(42L);

        // then
        assertThat(issued.value()).hasSize(43).matches("[A-Za-z0-9_-]+");
    }

    @Test
    void everyTokenIsDifferent() {
        // given

        // when
        IssuedRefreshToken first = service.issue(42L);
        IssuedRefreshToken second = service.issue(42L);

        // then
        assertThat(first.value()).isNotEqualTo(second.value());
        List<RefreshToken> saved = savedTokens(2);
        assertThat(saved.get(0).getTokenHash()).isNotEqualTo(saved.get(1).getTokenHash());
    }

    @Test
    void recordsOwnerTimesAndLeavesTheTokenUsable() {
        // given

        // when
        IssuedRefreshToken issued = service.issue(42L);

        // then
        RefreshToken saved = savedTokens(1).getFirst();
        assertThat(saved.getUserId()).isEqualTo(42L);
        assertThat(saved.getCreatedAt()).isEqualTo(T0);
        assertThat(saved.getExpiresAt()).isEqualTo(T0.plus(Duration.ofDays(30)));
        assertThat(issued.expiresAt()).isEqualTo(saved.getExpiresAt());
        assertThat(saved.getRevokedAt()).isNull();
    }

    @Test
    void eachLoginStartsANewFamily() {
        // given

        // when
        service.issue(42L);
        service.issue(42L);

        // then
        List<RefreshToken> saved = savedTokens(2);
        assertThat(saved.get(0).getFamilyId()).hasSize(36).isNotEqualTo(saved.get(1).getFamilyId());
    }

    @Test
    void rotationKeepsTheSameFamily() {
        // given

        // when
        service.issue(42L, "family-1");
        service.issue(42L, "family-1");

        // then
        assertThat(savedTokens(2)).extracting(RefreshToken::getFamilyId).containsOnly("family-1");
    }

    @Test
    void hashMatchesTheKnownSha256Vector() {
        // given / when
        String hash = RefreshTokenService.hash("abc");

        // then
        assertThat(hash).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    private RefreshToken storedToken(String raw, Instant expiresAt, Instant revokedAt) {
        RefreshToken token = new RefreshToken();
        token.setUserId(42L);
        token.setTokenHash(RefreshTokenService.hash(raw));
        token.setFamilyId("family-1");
        token.setCreatedAt(T0.minusSeconds(60));
        token.setExpiresAt(expiresAt);
        token.setRevokedAt(revokedAt);
        return token;
    }

    @Test
    void rotateReplacesTheTokenAndKeepsTheFamily() {
        // given
        RefreshToken old = storedToken("old-raw", T0.plus(Duration.ofDays(1)), null);
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash("old-raw")))
                .thenReturn(Optional.of(old));

        // when
        RefreshRotation rotation = service.rotate("old-raw");

        // then
        assertThat(rotation.status()).isEqualTo(RefreshRotation.Status.ROTATED);
        assertThat(rotation.userId()).isEqualTo(42L);
        assertThat(rotation.token().value()).isNotEqualTo("old-raw");
        assertThat(old.getRevokedAt()).isEqualTo(T0);
        RefreshToken created = savedTokens(1).get(0);
        assertThat(created.getFamilyId()).isEqualTo("family-1");
        assertThat(created.getUserId()).isEqualTo(42L);
        assertThat(created.getTokenHash()).isEqualTo(RefreshTokenService.hash(rotation.token().value()));
    }

    @Test
    void rotateRejectsUnknownTokens() {
        // given
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash("unknown")))
                .thenReturn(Optional.empty());

        // when
        RefreshRotation rotation = service.rotate("unknown");

        // then
        assertThat(rotation.status()).isEqualTo(RefreshRotation.Status.INVALID);
        verify(repository, never()).save(any(RefreshToken.class));
    }

    @Test
    void rotateRejectsExpiredTokensWithoutRevokingTheFamily() {
        // given
        RefreshToken expired = storedToken("expired-raw", T0, null);
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash("expired-raw")))
                .thenReturn(Optional.of(expired));

        // when
        RefreshRotation rotation = service.rotate("expired-raw");

        // then
        assertThat(rotation.status()).isEqualTo(RefreshRotation.Status.INVALID);
        verify(repository, never()).save(any(RefreshToken.class));
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void reusingAnAlreadyRotatedTokenRevokesTheWholeFamily() {
        // given
        RefreshToken used = storedToken("used-raw", T0.plus(Duration.ofDays(1)), T0.minusSeconds(5));
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash("used-raw")))
                .thenReturn(Optional.of(used));

        // when
        RefreshRotation rotation = service.rotate("used-raw");

        // then
        assertThat(rotation.status()).isEqualTo(RefreshRotation.Status.INVALID);
        verify(repository).revokeFamily("family-1", T0);
        verify(repository, never()).save(any(RefreshToken.class));
    }

    @Test
    void rotateRejectsBlankInputWithoutTouchingTheDatabase() {
        // given / when
        RefreshRotation blank = service.rotate("  ");
        RefreshRotation none = service.rotate(null);

        // then
        assertThat(blank.status()).isEqualTo(RefreshRotation.Status.INVALID);
        assertThat(none.status()).isEqualTo(RefreshRotation.Status.INVALID);
        verifyNoInteractions(repository);
    }

    @Test
    void revokeEndsTheWholeSession() {
        // given
        RefreshToken token = storedToken("raw", T0.plus(Duration.ofDays(1)), null);
        when(repository.findByTokenHash(RefreshTokenService.hash("raw"))).thenReturn(Optional.of(token));

        // when
        service.revoke("raw");

        // then
        verify(repository).revokeFamily("family-1", T0);
    }

    @Test
    void revokeIgnoresUnknownTokens() {
        // given
        when(repository.findByTokenHash(RefreshTokenService.hash("unknown"))).thenReturn(Optional.empty());

        // when
        service.revoke("unknown");

        // then
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void revokeAllForUserRevokesEverySession() {
        // given

        // when
        service.revokeAllFor(42L);

        // then
        verify(repository).revokeAllForUser(42L, T0);
    }
}