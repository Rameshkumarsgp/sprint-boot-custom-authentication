package org.example.sprintbootcustomauthentication.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.sprintbootcustomauthentication.token.AccessTokenClaims;
import org.example.sprintbootcustomauthentication.token.AccessTokenService;
import org.example.sprintbootcustomauthentication.token.InvalidTokenException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_PREFIX = "ROLE_";

    private final AccessTokenService accessTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            try {
                AccessTokenClaims claims = accessTokenService.parse(token);
                AuthenticatedUser principal =
                        new AuthenticatedUser(claims.userId(), claims.tokenId(), claims.expiresAt());

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(UsernamePasswordAuthenticationToken
                        .authenticated(principal, null, authoritiesOf(claims)));
                SecurityContextHolder.setContext(context);
            } catch (InvalidTokenException e) {
                log.debug("Ignoring invalid bearer token");
            }
        }

        filterChain.doFilter(request, response);
    }

    private static List<GrantedAuthority> authoritiesOf(AccessTokenClaims claims) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        claims.roles().forEach(role -> authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));
        claims.permissions().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        return authorities;
    }
}
