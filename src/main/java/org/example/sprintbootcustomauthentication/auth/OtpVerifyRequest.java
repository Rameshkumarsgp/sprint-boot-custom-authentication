package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OtpVerifyRequest(
        @NotBlank @Pattern(regexp = "\\d{10,15}",
                message = "must be 10-15 digits") String mobileNumber,
        @NotBlank @Pattern(regexp = "\\d{6}", message = "must be 6 digits") String otp) {
}
