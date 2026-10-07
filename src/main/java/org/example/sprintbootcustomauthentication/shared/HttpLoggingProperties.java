package org.example.sprintbootcustomauthentication.shared;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "app.http-logging")
public record HttpLoggingProperties(@DefaultValue("false") boolean logBodies,
                                    @DefaultValue("1000") int maxBodyLength) {
}
