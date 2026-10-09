package org.example.sprintbootcustomauthentication.user;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.shared.UserAuthorities;
import org.example.sprintbootcustomauthentication.user.internal.Role;
import org.example.sprintbootcustomauthentication.user.internal.RoleRepository;
import org.example.sprintbootcustomauthentication.user.internal.User;
import org.example.sprintbootcustomauthentication.user.internal.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.example.sprintbootcustomauthentication.shared.MobileNumber;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;
    private final RoleRepository roleRepository;
    private final Clock clock;

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public UserInfo findOrCreate(MobileNumber mobileNumber) {
        String number = mobileNumber.value();
        repository.insertIfAbsent(number, Instant.now(clock));

        User user = repository.findByMobileNumber(number)
                .orElseThrow(() -> new IllegalArgumentException("User missing right after insert"));

        roleRepository.grantDefaultRole(user.getId());

        return new UserInfo(user.getId(), user.getMobileNumber(), user.isEnabled());
    }

    @Transactional(readOnly = true)
    public Optional<UserInfo> findById(Long id) {
        return repository.findById(id)
                .map(user -> new UserInfo(user.getId(), user.getMobileNumber(), user.isEnabled()));
    }

    @Transactional(readOnly = true)
    public UserAuthorities authoritiesFor(Long userId) {
        return repository.findById(userId)
                .map(user -> {
                    Set<String> roles = new TreeSet<>();
                    Set<String> permissions = new TreeSet<>();
                    for (Role role : user.getRoles()) {
                        roles.add(role.getName());
                        permissions.addAll(role.getPermissions());
                    }
                    return new UserAuthorities(roles, permissions);
                })
                .orElseGet(UserAuthorities::empty);
    }
}
