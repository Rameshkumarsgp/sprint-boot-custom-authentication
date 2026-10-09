package org.example.sprintbootcustomauthentication.user.internal;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
class RoleSeeder implements ApplicationRunner {

    private static final Map<String, Set<String>> DEFAULT_ROLES = Map.of(
            "USER", Set.of("ACCOUNT_READ", "PROFILE_UPDATE"),
            "ADMIN", Set.of("ACCOUNT_READ", "ACCOUNT_UPDATE", "USER_DELETE"));

    private final RoleRepository roleRepository;

    @Override
    public void run(ApplicationArguments args) {
        DEFAULT_ROLES.forEach((name, permissions) -> {
            if (roleRepository.findByName(name).isEmpty()) {
                Role role = new Role();
                role.setName(name);
                role.setPermissions(new HashSet<>(permissions));
                roleRepository.save(role);
            }
        });
    }
}
