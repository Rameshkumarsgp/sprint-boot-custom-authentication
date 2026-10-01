package org.example.sprintbootcustomauthentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SprintBootCustomAuthenticationApplication {

    static void main(String[] args) {
        SpringApplication.run(SprintBootCustomAuthenticationApplication.class, args);
    }

}
