package com.security.jwt.config;

import com.security.jwt.filter.JwtTokenValidationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security config that adds JWT token filter in the spring security filter chain.
 *
 * @author Vasil
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenValidationFilter jwtTokenValidationFilter;

    /**
     * Add the filter to the security filter chain
     *
     * @param http the http security object
     * @return SecurityFilterChain security filter chain
     * @throws Exception Exception default exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(jwtTokenValidationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
