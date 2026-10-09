package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class TokenController {

    private final AuthenticationService authenticationService;

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest body) {
        return AuthResponses.from(authenticationService.refresh(body.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest body) {
        authenticationService.logout(body.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
