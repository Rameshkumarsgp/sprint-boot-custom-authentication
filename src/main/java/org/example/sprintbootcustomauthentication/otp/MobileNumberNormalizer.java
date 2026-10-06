package org.example.sprintbootcustomauthentication.otp;

public final class MobileNumberNormalizer {
    public static final String DEFAULT_COUNTRY_CODE = "91";

    public static String normalize(String rawMobileNumber) {
        if (rawMobileNumber == null) {
            throw new InvalidMobileNumberException();
        }
        String digits = rawMobileNumber.replaceAll("[\\s\\-()]", "");

        boolean international = false;
        if (digits.startsWith("+")) {
            digits = digits.substring(1);
            international = true;
        } else if (digits.startsWith("00")) {
            digits = digits.substring(2);
            international = true;
        }

        if (!digits.matches("\\d+")) {
            throw new InvalidMobileNumberException();
        }

        if (!international) {
            if (digits.startsWith("0")) {
                digits = DEFAULT_COUNTRY_CODE + digits.substring(1);
            } else if (digits.length() == 10) {
                digits = DEFAULT_COUNTRY_CODE + digits;
            }
        }

        return digits;
    }
}
