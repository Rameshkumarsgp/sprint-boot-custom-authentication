package org.example.sprintbootcustomauthentication.demo;

import org.example.sprintbootcustomauthentication.security.SecurityConfig;
import org.example.sprintbootcustomauthentication.token.AccessTokenClaims;
import org.example.sprintbootcustomauthentication.token.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Set;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DemoController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("dev")
class DemoControllerTest {

    private static final Instant EXPIRY = Instant.parse("2026-01-01T00:15:00Z");

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        when(accessTokenService.parse("user-token")).thenReturn(new AccessTokenClaims(
                1L, "jti-user", EXPIRY, Set.of("USER"), Set.of("ACCOUNT_READ", "PROFILE_UPDATE")));
        when(accessTokenService.parse("admin-token")).thenReturn(new AccessTokenClaims(
                2L, "jti-admin", EXPIRY, Set.of("ADMIN"),
                Set.of("ACCOUNT_READ", "ACCOUNT_UPDATE", "USER_DELETE")));
        when(accessTokenService.parse("plain-token")).thenReturn(new AccessTokenClaims(3L, "jti-plain", EXPIRY));
    }

    @Test
    void userWithThePermissionCanReadAccounts() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/demo/accounts").header("Authorization", "Bearer user-token"));

        // then
        result.andExpect(status().isOk());
    }

    @Test
    void userWithoutThePermissionCannotUpdateAccounts() throws Exception {
        // given

        // when
        var result = mockMvc.perform(put("/demo/accounts/1").header("Authorization", "Bearer user-token"));

        // then
        result.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("FORBIDDEN"));
    }

    @Test
    void adminCanUpdateAccounts() throws Exception {
        // given

        // when
        var result = mockMvc.perform(put("/demo/accounts/1").header("Authorization", "Bearer admin-token"));

        // then
        result.andExpect(status().isNoContent());
    }

    @Test
    void userCannotDeleteUsersBecauseThatNeedsTheAdminRole() throws Exception {
        // given

        // when
        var result = mockMvc.perform(delete("/demo/users/9").header("Authorization", "Bearer user-token"));

        // then
        result.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("FORBIDDEN"));
    }

    @Test
    void adminCanDeleteUsers() throws Exception {
        // given

        // when
        var result = mockMvc.perform(delete("/demo/users/9").header("Authorization", "Bearer admin-token"));

        // then
        result.andExpect(status().isNoContent());
    }

    @Test
    void anonymousCallersGetUnauthorizedNotForbidden() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/demo/accounts"));

        // then
        result.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
    }

    @Test
    void authenticatedUserWithNoAuthoritiesIsForbidden() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/demo/accounts").header("Authorization", "Bearer plain-token"));

        // then
        result.andExpect(status().isForbidden());
    }
}
