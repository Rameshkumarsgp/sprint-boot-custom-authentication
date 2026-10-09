package org.example.sprintbootcustomauthentication.user.internal;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

    @Modifying
    @Query(value = """
            insert ignore into user_roles (user_id, role_id)
            select :userId, r.id from roles r
            where r.name = 'USER'
              and not exists (select 1 from user_roles ur where ur.user_id = :userId)
            """, nativeQuery = true)
    void grantDefaultRole(@Param("userId") Long userId);
}
