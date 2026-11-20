package com.sanitizedb.governance;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
public class GovernanceCoreApplication {
    public static void main(String[] args) {
        SpringApplication.run(GovernanceCoreApplication.class, args);
    }
}
