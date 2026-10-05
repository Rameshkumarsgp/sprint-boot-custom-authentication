package org.example.sprintbootcustomauthentication.otp.internal;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, Long> {

    Optional<Otp> findByMobileNumber(String mobileNumber);

    @Modifying
    @Query(value = """
            insert into otp (mobile_number, otp_hash, expires_at, attempts)
            values (:mobileNumber, :otpHash, :expiresAt, 0)
            on duplicate key update
                otp_hash = values(otp_hash),
                expires_at = values(expires_at),
                attempts = 0
            """, nativeQuery = true)
    void upsert(@Param("mobileNumber") String mobileNumber,
                @Param("otpHash") String otpHash,
                @Param("expiresAt") Instant expiresAt);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select o from Otp o where o.mobileNumber = :mobileNumber")
    Optional<Otp> findByMobileNumberForUpdate(@Param("mobileNumber") String mobileNumber);
}
