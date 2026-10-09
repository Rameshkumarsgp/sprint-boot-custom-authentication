package org.example.sprintbootcustomauthentication.user;

import org.example.sprintbootcustomauthentication.shared.MobileNumber;
import org.example.sprintbootcustomauthentication.shared.UserAuthorities;
import org.example.sprintbootcustomauthentication.user.internal.Role;
import org.example.sprintbootcustomauthentication.user.internal.RoleRepository;
import org.example.sprintbootcustomauthentication.user.internal.User;
import org.example.sprintbootcustomauthentication.user.internal.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final MobileNumber MOBILE = new MobileNumber("919876543210");
    private static final String NUMBER = MOBILE.value();
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Mock
    UserRepository repository;

    @Mock
    RoleRepository roleRepository;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(repository, roleRepository, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private User storedUser(long id, boolean enabled) {
        User user = new User();
        user.setId(id);
        user.setMobileNumber(NUMBER);
        user.setEnabled(enabled);
        user.setCreatedAt(NOW);
        return user;
    }

    @Test
    void insertsIfAbsentThenReturnsTheStoredUser() {
        // given
        when(repository.findByMobileNumber(NUMBER)).thenReturn(Optional.of(storedUser(5L, true)));

        // when
        UserInfo result = userService.findOrCreate(MOBILE);

        // then
        InOrder order = inOrder(repository, roleRepository);
        order.verify(repository).insertIfAbsent(NUMBER, NOW);
        order.verify(repository).findByMobileNumber(NUMBER);
        order.verify(roleRepository).grantDefaultRole(5L);
        assertThat(result).isEqualTo(new UserInfo(5L, NUMBER, true));
    }

    @Test
    void existingDisabledUserIsReturnedAsIs() {
        // given
        when(repository.findByMobileNumber(NUMBER)).thenReturn(Optional.of(storedUser(9L, false)));

        // when
        UserInfo result = userService.findOrCreate(MOBILE);

        // then
        assertThat(result.enabled()).isFalse();
        assertThat(result.id()).isEqualTo(9L);
    }

    @Test
    void failsIfTheUserIsMissingRightAfterTheInsert() {
        // given
        when(repository.findByMobileNumber(NUMBER)).thenReturn(Optional.empty());

        // when / then
        assertThatThrownBy(() -> userService.findOrCreate(MOBILE))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("User missing");
    }

    @Test
    void findByIdReturnsTheUser() {
        // given
        when(repository.findById(5L)).thenReturn(Optional.of(storedUser(5L, true)));

        // when
        Optional<UserInfo> result = userService.findById(5L);

        // then
        assertThat(result).contains(new UserInfo(5L, NUMBER, true));
    }

    @Test
    void findByIdReturnsEmptyForAnUnknownUser() {
        // given
        when(repository.findById(99L)).thenReturn(Optional.empty());

        // when
        Optional<UserInfo> result = userService.findById(99L);

        // then
        assertThat(result).isEmpty();
    }

    private Role role(String name, String... permissions) {
        Role role = new Role();
        role.setName(name);
        role.setPermissions(Set.of(permissions));
        return role;
    }

    @Test
    void authoritiesCombineAllRolesAndTheirPermissions() {
        // given
        User stored = storedUser(5L, true);
        stored.setRoles(Set.of(
                role("USER", "ACCOUNT_READ", "PROFILE_UPDATE"),
                role("ADMIN", "ACCOUNT_READ", "USER_DELETE")));
        when(repository.findById(5L)).thenReturn(Optional.of(stored));

        // when
        UserAuthorities result = userService.authoritiesFor(5L);

        // then
        assertThat(result.roles()).containsExactlyInAnyOrder("USER", "ADMIN");
        assertThat(result.permissions())
                .containsExactlyInAnyOrder("ACCOUNT_READ", "PROFILE_UPDATE", "USER_DELETE");
    }

    @Test
    void anUnknownUserHasNoAuthorities() {
        // given
        when(repository.findById(99L)).thenReturn(Optional.empty());

        // when
        UserAuthorities result = userService.authoritiesFor(99L);

        // then
        assertThat(result.roles()).isEmpty();
        assertThat(result.permissions()).isEmpty();
    }
}
