package org.example.sprintbootcustomauthentication.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Sample endpoints for learning how authorization works. Delete this class when real
 * endpoints with permission checks exist.
 */
@RestController
@RequestMapping("/demo")
public class DemoController {

    @PreAuthorize("hasAuthority('ACCOUNT_READ')")
    @GetMapping("/accounts")
    public Map<String, Object> accounts() {
        return Map.of("accounts", List.of());
    }

    @PreAuthorize("hasAuthority('ACCOUNT_UPDATE')")
    @PutMapping("/accounts/{id}")
    public ResponseEntity<Void> updateAccount(@PathVariable Long id) {
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        return ResponseEntity.noContent().build();
    }
}
