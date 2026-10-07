package org.example.sprintbootcustomauthentication.user;

import lombok.RequiredArgsConstructor;
import org.example.sprintbootcustomauthentication.user.internal.User;
import org.example.sprintbootcustomauthentication.user.internal.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import shared.MobileNumber;

import java.time.Clock;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;
    private final Clock clock;

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public UserInfo findOrCreate(MobileNumber mobileNumber) {
        String number = mobileNumber.value();
        repository.insertIfAbsent(number, Instant.now(clock));

        User user = repository.findByMobileNumber(number)
                .orElseThrow(() -> new IllegalArgumentException("User missing right after insert"));

        return new UserInfo(user.getId(), user.getMobileNumber(), user.isEnabled());
    }
}
