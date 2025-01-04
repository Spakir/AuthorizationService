package org.example.authorizationservice.config;

import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.provider.CustomAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@RequiredArgsConstructor
public class FilterChainConfig {

    private final CustomAuthenticationProvider customAuthenticationProvider;

    @Bean
    SecurityFilterChain filterChai(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/success").authenticated()
                        .anyRequest().permitAll())

                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/success"))

                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))

                .logout(Customizer.withDefaults())

                .authenticationProvider(customAuthenticationProvider);

        return http.build();
    }
}
