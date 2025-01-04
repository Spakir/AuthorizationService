package org.example.authorizationservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
public class TokenService {

    private final WebClient webClient;

    public TokenService(WebClient.Builder web) {
        this.webClient = web.baseUrl("http://localhost:8080").build();
    }

    public Mono<String> exchangeAuthorizationCodeForToken(String code) {
        log.info("exchangeAuthCodeForToken: ");

        String clientId = "client";
        String clientSecret = "clientSecret";
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));

        return webClient.post()
                .uri("/oauth2/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + encodedAuth)
                .bodyValue("grant_type=authorization_code&" +
                        "code=" + code + "&" +
                        "redirect_uri=http://localhost:8080/success")
                .retrieve()
                .bodyToMono(String.class)
                .doOnError(e -> log.error("Ошибка при получении токена: {}", e.getMessage()))
                .onErrorResume(e -> Mono.empty());
    }


}
