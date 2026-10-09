package org.example.sprintbootcustomauthentication.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.example.sprintbootcustomauthentication.shared.UserAuthorities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AccessTokenServiceTest {

    private static final String SECRET = "unit-test-secret-unit-test-secret-0123";
    private static final SecretKey KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    private static AccessTokenService serviceAt(Instant now) {
        return service(SECRET, "auth-service", "auth-service-api", now);
    }

    private static AccessTokenService service(String secret, String issuer, String audience, Instant now) {
        TokenProperties properties = new TokenProperties(
                secret, issuer, audience, Duration.ofMinutes(15), Duration.ofDays(30));
        return new AccessTokenService(properties, Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void issuedTokenValidatesAndCarriesTheUserId() {
        // given
        AccessTokenService service = serviceAt(T0);
        AccessToken token = service.issue(42L);

        // when
        AccessTokenClaims claims = service.parse(token.value());

        // then
        assertThat(claims.userId()).isEqualTo(42L);
        assertThat(claims.tokenId()).isNotBlank();
        assertThat(token.expiresAt()).isEqualTo(T0.plus(Duration.ofMinutes(15)));
    }

    @Test
    void issuedTokenContainsTheExpectedClaims() {
        // given
        AccessToken token = serviceAt(T0).issue(42L);

        // when
        Claims claims = Jwts.parser().verifyWith(KEY).clock(() -> Date.from(T0)).build()
                .parseSignedClaims(token.value()).getPayload();

        // then
        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.getIssuer()).isEqualTo("auth-service");
        assertThat(claims.getAudience()).containsExactly("auth-service-api");
        assertThat(claims.getIssuedAt().toInstant()).isEqualTo(T0);
        assertThat(claims.getExpiration().toInstant()).isEqualTo(T0.plus(Duration.ofMinutes(15)));
        assertThat(claims.getId()).isNotBlank();
    }

    @Test
    void everyTokenGetsAUniqueId() {
        // given
        AccessTokenService service = serviceAt(T0);

        // when
        String first = service.parse(service.issue(42L).value()).tokenId();
        String second = service.parse(service.issue(42L).value()).tokenId();

        // then
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void tokenIsAcceptedJustBeforeItExpires() {
        // given
        AccessToken token = serviceAt(T0).issue(42L);

        // when
        AccessTokenClaims claims = serviceAt(T0.plus(Duration.ofMinutes(14))).parse(token.value());

        // then
        assertThat(claims.userId()).isEqualTo(42L);
    }

    @Test
    void expiredTokenIsRejected() {
        // given
        AccessToken token = serviceAt(T0).issue(42L);

        // when / then
        assertThatThrownBy(() -> serviceAt(T0.plus(Duration.ofMinutes(16))).parse(token.value()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void tamperedPayloadIsRejected() {
        // given
        String[] parts = serviceAt(T0).issue(42L).value().split("\\.");
        char first = parts[1].charAt(0);
        String forged = parts[0] + "." + (first == 'A' ? 'B' : 'A') + parts[1].substring(1) + "." + parts[2];

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(forged))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void tokenSignedWithAnotherKeyIsRejected() {
        // given
        AccessToken foreign = service("another-secret-another-secret-123456",
                "auth-service", "auth-service-api", T0).issue(42L);

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(foreign.value()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void tokenFromAnotherIssuerIsRejected() {
        // given
        AccessToken other = service(SECRET, "someone-else", "auth-service-api", T0).issue(42L);

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(other.value()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void tokenForAnotherAudienceIsRejected() {
        // given
        AccessToken other = service(SECRET, "auth-service", "another-api", T0).issue(42L);

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(other.value()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void unsignedTokenIsRejected() {
        // given
        String unsigned = Jwts.builder()
                .subject("42")
                .issuer("auth-service")
                .audience().add("auth-service-api").and()
                .compact();

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(unsigned))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validlySignedTokenWithoutExpiryIsRejected() {
        // given
        String noExpiry = Jwts.builder()
                .subject("42")
                .issuer("auth-service")
                .audience().add("auth-service-api").and()
                .signWith(KEY)
                .compact();

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(noExpiry))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validlySignedTokenWithANonNumericSubjectIsRejected() {
        // given
        String badSubject = Jwts.builder()
                .subject("not-a-number")
                .issuer("auth-service")
                .audience().add("auth-service-api").and()
                .expiration(Date.from(T0.plus(Duration.ofMinutes(15))))
                .signWith(KEY)
                .compact();

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(badSubject))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validlySignedTokenWithoutASubjectIsRejected() {
        // given
        String noSubject = Jwts.builder()
                .issuer("auth-service")
                .audience().add("auth-service-api").and()
                .expiration(Date.from(T0.plus(Duration.ofMinutes(15))))
                .signWith(KEY)
                .compact();

        // when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(noSubject))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void returnedExpiryMatchesTheTokenToTheSecond() {
        // given
        AccessTokenService service = serviceAt(T0.plusMillis(756));

        // when
        AccessToken token = service.issue(42L);

        // then
        assertThat(service.parse(token.value()).expiresAt()).isEqualTo(token.expiresAt());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"not-a-jwt", "a.b.c", "   "})
    void garbageIsRejected(String garbage) {
        // given / when / then
        assertThatThrownBy(() -> serviceAt(T0).parse(garbage))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void weakSecretIsRejectedAtStartup() {
        // given / when / then
        assertThatThrownBy(() -> service("too-short", "auth-service", "auth-service-api", T0))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rolesAndPermissionsTravelInsideTheToken() {
        // given
        AccessTokenService service = serviceAt(T0);
        UserAuthorities authorities =
                new UserAuthorities(Set.of("USER"), Set.of("ACCOUNT_READ", "PROFILE_UPDATE"));
        AccessToken token = service.issue(42L, authorities);

        // when
        AccessTokenClaims claims = service.parse(token.value());

        // then
        assertThat(claims.roles()).containsExactly("USER");
        assertThat(claims.permissions()).containsExactlyInAnyOrder("ACCOUNT_READ", "PROFILE_UPDATE");
    }

    @Test
    void tokenIssuedWithoutAuthoritiesHasNone() {
        // given
        AccessTokenService service = serviceAt(T0);

        // when
        AccessTokenClaims claims = service.parse(service.issue(42L).value());

        // then
        assertThat(claims.roles()).isEmpty();
        assertThat(claims.permissions()).isEmpty();
    }

    @Test
    void validlySignedTokenWithoutAuthorityClaimsParsesWithNoAuthorities() {
        // given
        String plain = Jwts.builder()
                .subject("42")
                .issuer("auth-service")
                .audience().add("auth-service-api").and()
                .expiration(Date.from(T0.plus(Duration.ofMinutes(15))))
                .signWith(KEY)
                .compact();

        // when
        AccessTokenClaims claims = serviceAt(T0).parse(plain);

        // then
        assertThat(claims.roles()).isEmpty();
        assertThat(claims.permissions()).isEmpty();
    }
}
