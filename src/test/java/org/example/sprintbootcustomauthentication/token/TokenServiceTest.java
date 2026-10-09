package org.example.sprintbootcustomauthentication.token;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    @Mock
    AccessTokenService accessTokenService;

    @Mock
    RefreshTokenService refreshTokenService;

    @Test
    void issuesBothTokensForTheUser() {
        // given
        TokenProperties properties = new TokenProperties(
                "unit-test-secret-unit-test-secret-0123", "auth-service", "auth-service-api",
                Duration.ofMinutes(15), Duration.ofDays(30));
        TokenService service = new TokenService(accessTokenService, refreshTokenService, properties);
        AccessToken access = new AccessToken("access.jwt.value", T0.plus(Duration.ofMinutes(15)));
        IssuedRefreshToken refresh = new IssuedRefreshToken("refresh-value", T0.plus(Duration.ofDays(30)));
        when(accessTokenService.issue(42L)).thenReturn(access);
        when(refreshTokenService.issue(42L)).thenReturn(refresh);

        // when
        TokenPair pair = service.issueFor(42L);

        // then
        assertThat(pair.accessToken()).isEqualTo(access);
        assertThat(pair.refreshToken()).isEqualTo(refresh);
        assertThat(pair.expiresInSeconds()).isEqualTo(900);
    }
}
