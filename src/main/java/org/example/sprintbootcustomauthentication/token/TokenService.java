package org.example.sprintbootcustomauthentication.token;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final TokenProperties properties;

    public TokenPair issueFor(Long userId) {
        return new TokenPair(
                accessTokenService.issue(userId),
                refreshTokenService.issue(userId),
                properties.accessTtl().toSeconds());
    }
}
