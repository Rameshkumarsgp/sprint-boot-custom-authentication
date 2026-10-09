package org.example.sprintbootcustomauthentication.shared;

import java.util.Set;

public record UserAuthorities(Set<String> roles, Set<String> permissions) {

    public UserAuthorities {
        roles = Set.copyOf(roles);
        permissions = Set.copyOf(permissions);
    }

    public static UserAuthorities empty() {
        return new UserAuthorities(Set.of(), Set.of());
    }
}
