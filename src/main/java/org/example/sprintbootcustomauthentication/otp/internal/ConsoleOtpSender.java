package org.example.sprintbootcustomauthentication.otp.internal;

import lombok.extern.slf4j.Slf4j;
import org.example.sprintbootcustomauthentication.otp.OtpSender;
import org.springframework.stereotype.Component;

@Slf4j
@Component
 class ConsoleOtpSender implements OtpSender {

    @Override
    public void send(String mobileNumber, String otp) {
        log.info("OTP for {} = {}", mobileNumber, otp);
    }

}
