package org.example.sprintbootcustomauthentication.user;

import org.example.sprintbootcustomauthentication.shared.MobileNumber;
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

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(repository, Clock.fixed(NOW, ZoneOffset.UTC));
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
        InOrder order = inOrder(repository);
        order.verify(repository).insertIfAbsent(NUMBER, NOW);
        order.verify(repository).findByMobileNumber(NUMBER);
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
}
