package org.example.sprintbootcustomauthentication.token;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.shared.UserAuthorities;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final TokenProperties properties;

    public TokenPair issueFor(Long userId, UserAuthorities authorities) {
        return pairFor(userId, authorities, refreshTokenService.issue(userId));
    }

    public TokenPair pairFor(Long userId, UserAuthorities authorities, IssuedRefreshToken refreshToken) {
        return new TokenPair(
                accessTokenService.issue(userId, authorities),
                refreshToken,
                properties.accessTtl().toSeconds());
    }

    public RefreshRotation rotateRefreshToken(String rawRefreshToken) {
        return refreshTokenService.rotate(rawRefreshToken);
    }

    public void logout(String rawRefreshToken) {
        refreshTokenService.revoke(rawRefreshToken);
    }

    public void revokeAllFor(Long userId) {
        refreshTokenService.revokeAllFor(userId);
    }
}
