package org.example.sprintbootcustomauthentication.user.internal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleSeederTest {

    @Mock
    RoleRepository roleRepository;

    @Test
    void createsTheDefaultRolesWhenTheyAreMissing() {
        // given
        when(roleRepository.findByName(anyString())).thenReturn(Optional.empty());

        // when
        new RoleSeeder(roleRepository).run(null);

        // then
        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository, times(2)).save(captor.capture());
        assertThat(captor.getAllValues()).extracting(Role::getName).containsExactlyInAnyOrder("USER", "ADMIN");
        Role user = captor.getAllValues().stream().filter(r -> r.getName().equals("USER")).findFirst().orElseThrow();
        Role admin = captor.getAllValues().stream().filter(r -> r.getName().equals("ADMIN")).findFirst().orElseThrow();
        assertThat(user.getPermissions()).containsExactlyInAnyOrder("ACCOUNT_READ", "PROFILE_UPDATE");
        assertThat(admin.getPermissions())
                .containsExactlyInAnyOrder("ACCOUNT_READ", "ACCOUNT_UPDATE", "USER_DELETE");
    }

    @Test
    void leavesExistingRolesUntouched() {
        // given
        when(roleRepository.findByName(anyString())).thenReturn(Optional.of(new Role()));

        // when
        new RoleSeeder(roleRepository).run(null);

        // then
        verify(roleRepository, never()).save(any(Role.class));
    }
}
