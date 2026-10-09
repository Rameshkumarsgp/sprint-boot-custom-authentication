package org.example.sprintbootcustomauthentication.token;

import org.example.sprintbootcustomauthentication.shared.UserAuthorities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final UserAuthorities AUTHORITIES =
            new UserAuthorities(Set.of("USER"), Set.of("ACCOUNT_READ"));

    @Mock
    AccessTokenService accessTokenService;

    @Mock
    RefreshTokenService refreshTokenService;

    private TokenService service() {
        TokenProperties properties = new TokenProperties(
                "unit-test-secret-unit-test-secret-0123", "auth-service", "auth-service-api",
                Duration.ofMinutes(15), Duration.ofDays(30));
        return new TokenService(accessTokenService, refreshTokenService, properties);
    }

    @Test
    void issuesBothTokensForTheUser() {
        // given
        AccessToken access = new AccessToken("access.jwt.value", T0.plus(Duration.ofMinutes(15)));
        IssuedRefreshToken refresh = new IssuedRefreshToken("refresh-value", T0.plus(Duration.ofDays(30)));
        when(accessTokenService.issue(42L, AUTHORITIES)).thenReturn(access);
        when(refreshTokenService.issue(42L)).thenReturn(refresh);

        // when
        TokenPair pair = service().issueFor(42L, AUTHORITIES);

        // then
        assertThat(pair.accessToken()).isEqualTo(access);
        assertThat(pair.refreshToken()).isEqualTo(refresh);
        assertThat(pair.expiresInSeconds()).isEqualTo(900);
    }

    @Test
    void pairForWrapsTheGivenRefreshTokenWithAFreshAccessToken() {
        // given
        AccessToken access = new AccessToken("access.jwt.value", T0.plus(Duration.ofMinutes(15)));
        IssuedRefreshToken refresh = new IssuedRefreshToken("rotated-refresh", T0.plus(Duration.ofDays(30)));
        when(accessTokenService.issue(42L, AUTHORITIES)).thenReturn(access);

        // when
        TokenPair pair = service().pairFor(42L, AUTHORITIES, refresh);

        // then
        assertThat(pair.accessToken()).isEqualTo(access);
        assertThat(pair.refreshToken()).isEqualTo(refresh);
        verifyNoInteractions(refreshTokenService);
    }

    @Test
    void logoutAndRevokeAllDelegateToTheRefreshTokenService() {
        // given

        // when
        service().logout("raw");
        service().revokeAllFor(42L);

        // then
        verify(refreshTokenService).revoke("raw");
        verify(refreshTokenService).revokeAllFor(42L);
    }
}
