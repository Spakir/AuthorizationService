package org.example.authorizationservice.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
public class TokenService {

    private final WebClient webClient;

    public TokenService(WebClient.Builder web) {
        this.webClient = web.baseUrl("http://localhost:8080").build();
    }

    public Mono<String> exchangeAuthorizationCodeForToken(String code, HttpServletResponse response) {
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
                .onErrorResume(e -> Mono.empty())
                .doOnNext(jsonResponse -> {
                    JSONObject jsonObject = new JSONObject(jsonResponse);
                    String accessToken = jsonObject.getString("access_token");

                    Cookie cookie = new Cookie("JWT", accessToken);
                    cookie.setHttpOnly(false);
                    cookie.setPath("/");
                    cookie.setMaxAge(3600);
                    cookie.setSecure(false);

                    response.addCookie(cookie);
                })
                .then(Mono.fromRunnable(() -> {
                    try {
                        // Устанавливаем редирект на /hello
                        response.sendRedirect("/chat");
                    } catch (IOException e) {
                        // Обработка исключений
                        e.printStackTrace();
                    }
                }));
    }


}
