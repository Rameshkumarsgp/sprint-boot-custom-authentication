package org.example.sprintbootcustomauthentication.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record OtpRequest(@NotBlank
                         @Pattern(regexp = "[+0-9()\\-\\s]{10,20}", message = "must be a valid mobile number")
                         String mobileNumber) {
}
