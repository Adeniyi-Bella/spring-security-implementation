package com.example.demo.config;

import com.example.demo.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

// tells spring to inject the beans
@Configuration
// incase we want to implement a final class
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository repository;

 /*   public ApplicationConfig(UserRepository repository) {
        this.repository = repository;
    }*/

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
