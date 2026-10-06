package org.example.sprintbootcustomauthentication.otp;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MobileNumberNormalizerTest {

    @ParameterizedTest
    @CsvSource({
            "9876543210, 919876543210",
            "09876543210, 919876543210",
            "'+91 98765-43210', 919876543210",
            "'(+91) 98765 43210', 919876543210",
            "919876543210, 919876543210",
            "00919876543210, 919876543210",
            "+14155552671, 14155552671"
    })
    void normalizesToCanonicalDigits(String raw, String expected) {
        // given

        // when
        String result = MobileNumberNormalizer.normalize(raw);

        // then
        assertThat(result).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "", "+", "12345", "98765abc43", "9876543210123456789"})
    void rejectsInvalidNumbers(String raw) {
        // given

        // when / then
        assertThatThrownBy(() -> MobileNumberNormalizer.normalize(raw))
                .isInstanceOf(InvalidMobileNumberException.class);
    }
}