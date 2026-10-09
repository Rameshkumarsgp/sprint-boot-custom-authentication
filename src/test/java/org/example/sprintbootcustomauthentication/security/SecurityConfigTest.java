package org.example.sprintbootcustomauthentication.security;

import org.example.sprintbootcustomauthentication.auth.AuthController;
import org.example.sprintbootcustomauthentication.auth.AuthenticationService;
import org.example.sprintbootcustomauthentication.auth.MeController;
import org.example.sprintbootcustomauthentication.token.AccessTokenClaims;
import org.example.sprintbootcustomauthentication.token.AccessTokenService;
import org.example.sprintbootcustomauthentication.token.InvalidTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({AuthController.class, MeController.class})
@Import(SecurityConfig.class)
@ActiveProfiles("dev")
class SecurityConfigTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    AccessTokenService accessTokenService;

    @MockitoBean
    AuthenticationService authenticationService;

    @BeforeEach
    void setUp() {
        when(accessTokenService.parse("good-token"))
                .thenReturn(new AccessTokenClaims(42L, "jti-1", Instant.parse("2026-01-01T00:15:00Z")));
        when(accessTokenService.parse("bad-token")).thenThrow(new InvalidTokenException());
    }

    @Test
    void protectedEndpointWithoutTokenIsUnauthorized() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/me"));

        // then
        result.andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
    }

    @Test
    void validTokenReachesTheProtectedEndpoint() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/me").header("Authorization", "Bearer good-token"));

        // then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(42))
                .andExpect(jsonPath("$.tokenId").value("jti-1"));
    }

    @Test
    void bearerSchemeIsCaseInsensitive() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/me").header("Authorization", "bearer good-token"));

        // then
        result.andExpect(status().isOk());
    }

    @Test
    void invalidTokenIsUnauthorized() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/me").header("Authorization", "Bearer bad-token"));

        // then
        result.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
    }

    @Test
    void otherAuthorizationSchemesAreIgnored() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/me").header("Authorization", "Basic YWJjOmRlZg=="));

        // then
        result.andExpect(status().isUnauthorized());
        verifyNoInteractions(accessTokenService);
    }

    @Test
    void publicEndpointIgnoresABadToken() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/otp/request")
                .header("Authorization", "Bearer bad-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210"}
                        """));

        // then
        result.andExpect(status().isAccepted());
    }

    @Test
    void postWithoutCsrfTokenIsAllowedOnPublicEndpoints() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/otp/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210"}
                        """));

        // then
        result.andExpect(status().isAccepted());
    }

    @Test
    void unknownPathsAreUnauthorizedNotNotFound() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/does-not-exist"));

        // then
        result.andExpect(status().isUnauthorized());
    }

    @Test
    void securityHeadersAreSent() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/me"));

        // then
        result.andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }
}
