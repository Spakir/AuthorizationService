package org.example.authorizationservice.config;

import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.provider.CustomAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class FilterChainConfig {

   private final String REDIRECT_URI = "http://localhost:8080/oauth2/authorize?"+
           "response_type=code&client_id=client&redirect_uri=http://localhost:8080/success&scope=CUSTOM";

    private final CustomAuthenticationProvider customAuthenticationProvider;

    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    @Order(1)
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http.exceptionHandling((e) ->
                e.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/index"))
        );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain formLoginFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/index","/","/register").permitAll()
                        .anyRequest().authenticated())

                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl(REDIRECT_URI))

                .csrf(Customizer.withDefaults())

                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource))

                .logout(Customizer.withDefaults())

                .authenticationProvider(customAuthenticationProvider);

        return http.build();
    }
}
