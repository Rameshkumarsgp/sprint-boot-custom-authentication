package org.example.sprintbootcustomauthentication.auth;

import org.example.sprintbootcustomauthentication.security.SecurityConfig;
import org.example.sprintbootcustomauthentication.token.AccessToken;
import org.example.sprintbootcustomauthentication.token.AccessTokenService;
import org.example.sprintbootcustomauthentication.token.IssuedRefreshToken;
import org.example.sprintbootcustomauthentication.token.TokenPair;
import org.example.sprintbootcustomauthentication.user.UserInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("dev")
class TokenControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    AccessTokenService accessTokenService;

    @MockitoBean
    AuthenticationService authenticationService;

    private static final String BODY = """
            {"refreshToken":"raw-refresh"}
            """;

    @Test
    void refreshReturnsANewTokenPair() throws Exception {
        // given
        TokenPair tokens = new TokenPair(
                new AccessToken("new.access.jwt", Instant.parse("2026-01-01T00:15:00Z")),
                new IssuedRefreshToken("new-refresh", Instant.parse("2026-01-31T00:00:00Z")),
                900);
        when(authenticationService.refresh("raw-refresh"))
                .thenReturn(AuthResult.authenticated(new UserInfo(42L, "919876543210", true), tokens));

        // when
        var result = mockMvc.perform(post("/auth/token/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY));

        // then
        result.andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.accessToken").value("new.access.jwt"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.userId").value(42));
    }

    @Test
    void invalidRefreshTokenIsUnauthorized() throws Exception {
        // given
        when(authenticationService.refresh("raw-refresh"))
                .thenReturn(AuthResult.of(AuthResult.Status.INVALID_REFRESH_TOKEN));

        // when
        var result = mockMvc.perform(post("/auth/token/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY));

        // then
        result.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    void disabledAccountIsForbidden() throws Exception {
        // given
        when(authenticationService.refresh("raw-refresh"))
                .thenReturn(AuthResult.of(AuthResult.Status.ACCOUNT_DISABLED));

        // when
        var result = mockMvc.perform(post("/auth/token/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY));

        // then
        result.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ACCOUNT_DISABLED"));
    }

    @Test
    void blankRefreshTokenFailsValidation() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/token/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"refreshToken":""}
                        """));

        // then
        result.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.details.refreshToken").exists());
        verifyNoInteractions(authenticationService);
    }

    @Test
    void logoutRevokesTheSessionAndReturnsNoContent() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY));

        // then
        result.andExpect(status().isNoContent())
                .andExpect(content().string(""));
        verify(authenticationService).logout("raw-refresh");
    }
}
