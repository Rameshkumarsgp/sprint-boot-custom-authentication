package org.example.sprintbootcustomauthentication.auth;

import org.example.sprintbootcustomauthentication.otp.OtpResult;
import org.example.sprintbootcustomauthentication.otp.OtpService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@ActiveProfiles("dev")
class AuthControllerTest {

    private static final String MOBILE = "9876543210";

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    OtpService otpService;

    @Test
    void requestOtpReturnsAccepted() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/otp/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210"}
                        """));

        // then
        result.andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value("OTP sent"));
        verify(otpService).issue(MOBILE);
    }

    @Test
    void invalidMobileFailsValidation() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/otp/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"abc"}
                        """));

        // then
        result.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.details.mobileNumber").exists());
        verifyNoInteractions(otpService);
    }

    @Test
    void brokenJsonIsMalformedRequest() throws Exception {
        // given

        // when
        var result = mockMvc.perform(post("/auth/otp/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{bad json"));

        // then
        result.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST"));
    }

    @Test
    void verifiedOtpReturnsOk() throws Exception {
        // given
        when(otpService.verify(MOBILE, "483921")).thenReturn(OtpResult.VERIFIED);

        // when
        var result = mockMvc.perform(post("/auth/otp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210","otp":"483921"}
                        """));

        // then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true));
    }

    @ParameterizedTest
    @EnumSource(value = OtpResult.class, names = {"INVALID", "EXPIRED", "NOT_FOUND"})
    void rejectedOtpReturnsUnauthorizedWithSameMessage(OtpResult outcome) throws Exception {
        // given
        when(otpService.verify(MOBILE, "000000")).thenReturn(outcome);

        // when
        var result = mockMvc.perform(post("/auth/otp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210","otp":"000000"}
                        """));

        // then
        result.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_OR_EXPIRED_OTP"));
    }

    @Test
    void tooManyAttemptsReturns429() throws Exception {
        // given
        when(otpService.verify(MOBILE, "000000")).thenReturn(OtpResult.TOO_MANY_ATTEMPTS);

        // when
        var result = mockMvc.perform(post("/auth/otp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210","otp":"000000"}
                        """));

        // then
        result.andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("TOO_MANY_ATTEMPTS"));
    }

    @Test
    void unexpectedErrorHidesInternalDetails() throws Exception {
        // given
        doThrow(new RuntimeException("select * from otp where secret=1"))
                .when(otpService).issue(any());

        // when
        var result = mockMvc.perform(post("/auth/otp/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"mobileNumber":"9876543210"}
                        """));

        // then
        result.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("INTERNAL_ERROR"))
                .andExpect(content().string(not(containsString("select"))));
    }

    @Test
    void wrongHttpMethodReturns405() throws Exception {
        // given

        // when
        var result = mockMvc.perform(get("/auth/otp/request"));

        // then
        result.andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("METHOD_NOT_ALLOWED"));
    }
}
