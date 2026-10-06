package org.example.sprintbootcustomauthentication.user.internal;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    //
    Optional<User> findByMobileNumber(String mobileNumber);

    @Modifying
    @Query(value = """
            insert into users (mobile_number, enabled, created_at)
            values (:mobileNumber, true, :createdAt)
            on duplicate key update id = id
            """, nativeQuery = true)
    void insertIfAbsent(@Param("mobileNumber") String mobileNumber,
                        @Param("createdAt") Instant createdAt);
}
