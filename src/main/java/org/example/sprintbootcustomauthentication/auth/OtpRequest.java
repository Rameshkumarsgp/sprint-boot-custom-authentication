package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OtpRequest(@NotBlank
                         @Pattern(regexp = "\\d{10,15}", message = "must be 10-15 digits")
                         String mobileNumber) {
}
