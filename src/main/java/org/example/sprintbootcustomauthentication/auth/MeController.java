package org.example.sprintbootcustomauthentication.auth;

import org.example.sprintbootcustomauthentication.security.AuthenticatedUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
public class MeController {

    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal AuthenticatedUser user) {
        return new MeResponse(user.userId(), user.tokenId(), user.expiresAt());
    }

    public record MeResponse(Long userId, String tokenId, Instant expiresAt) {
    }
}
