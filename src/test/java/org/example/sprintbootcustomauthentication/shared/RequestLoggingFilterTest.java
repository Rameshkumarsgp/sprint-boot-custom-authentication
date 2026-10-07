package org.example.sprintbootcustomauthentication.shared;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequestLoggingFilterTest {

    @Test
    void masksOtpAndMobileNumber() {
        // given
        String body = "{\"mobileNumber\":\"+91 98765 43210\",\"otp\":\"483921\"}";

        // when
        String masked = RequestLoggingFilter.mask(body);

        // then
        assertThat(masked).doesNotContain("483921").doesNotContain("98765");
        assertThat(masked).contains("\"otp\":\"***\"").contains("3210");
    }

    @Test
    void masksTokens() {
        // given
        String body = "{\"accessToken\":\"abc.def.ghi\",\"refreshToken\":\"xyz\"}";

        // when
        String masked = RequestLoggingFilter.mask(body);

        // then
        assertThat(masked).doesNotContain("abc.def.ghi").doesNotContain("xyz");
    }

    @Test
    void keepsAFreshSafeRequestId() {
        // given / when
        String id = RequestLoggingFilter.resolveRequestId("abc-123_X.y");

        // then
        assertThat(id).isEqualTo("abc-123_X.y");
    }

    @Test
    void replacesUnsafeRequestIds() {
        // given / when
        String id = RequestLoggingFilter.resolveRequestId("bad\nid with spaces");

        // then
        assertThat(id).doesNotContain("\n").doesNotContain(" ").hasSize(36);
    }
}
