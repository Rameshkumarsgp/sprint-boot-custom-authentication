package org.example.sprintbootcustomauthentication.otp.internal;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, Long> {
    //
    Optional<Otp> findByMobileNumber(String mobileNumber);

}
