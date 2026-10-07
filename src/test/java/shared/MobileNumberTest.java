package shared;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MobileNumberTest {

    @Test
    void ofNormalizesRawInput() {
        // given

        // when
        MobileNumber number = MobileNumber.of("+91 98765-43210");

        // then
        assertThat(number.value()).isEqualTo("919876543210");
    }

    @Test
    void differentSpellingsOfTheSameNumberAreEqual() {
        // given

        // when
        MobileNumber fromLocal = MobileNumber.of("9876543210");
        MobileNumber fromCanonical = new MobileNumber("919876543210");

        // then
        assertThat(fromLocal).isEqualTo(fromCanonical);
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "", "12345", "+919876543210", "9876543210123456789"})
    void constructorRejectsNonCanonicalValues(String value) {
        // given

        // when / then
        assertThatThrownBy(() -> new MobileNumber(value))
                .isInstanceOf(InvalidMobileNumberException.class);
    }

    @Test
    void constructorRejectsNull() {
        // given

        // when / then
        assertThatThrownBy(() -> new MobileNumber(null))
                .isInstanceOf(InvalidMobileNumberException.class);
    }

    @Test
    void toStringMasksAllButLastFourDigits() {
        // given
        MobileNumber number = new MobileNumber("919876543210");

        // when
        String text = number.toString();

        // then
        assertThat(text).isEqualTo("********3210").doesNotContain("98765");
    }
}
