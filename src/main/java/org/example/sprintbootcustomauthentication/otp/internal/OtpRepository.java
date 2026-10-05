package org.example.sprintbootcustomauthentication.otp.internal;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, Long> {

    Optional<Otp> findByMobileNumber(String mobileNumber);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select o from Otp o where o.mobileNumber = :mobileNumber")
    Optional<Otp> findByMobileNumberForUpdate(@Param("mobileNumber") String mobileNumber);
}
