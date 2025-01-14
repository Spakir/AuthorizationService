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

    private final String ACCESS_TOKEN_NAME = "JWT";
    private final String ACCESS_TOKEN_PATH = "/";
    private final int ACCESS_TOKEN_EXPIRY = 3600;
    private final boolean ACCESS_TOKEN_HTTP_ONLY = false;
    private final boolean ACCESS_TOKEN_SECURE = false;


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
                    log.info("Json response: ");
                    JSONObject jsonObject = new JSONObject(jsonResponse);
                    String accessToken = jsonObject.getString("access_token");
                    String refreshToken = jsonObject.getString("refresh_token");

                    log.info("refresh token : {}", refreshToken);

                    String refreshTokenName = "refreshToken";
                    String refreshTokenPath = "/";
                    int refreshTokenExpiry = 3600 * 24 * 30;
                    boolean refreshTokenHttpOnly = false;
                    boolean refreshTokenSecure = false;

                    createNewCookie(refreshTokenName,
                            refreshToken, refreshTokenHttpOnly,
                            refreshTokenPath,
                            refreshTokenExpiry,
                            refreshTokenSecure,
                            response);

                    createNewCookie(ACCESS_TOKEN_NAME,
                            accessToken,
                            ACCESS_TOKEN_HTTP_ONLY,
                            ACCESS_TOKEN_PATH,
                            ACCESS_TOKEN_EXPIRY,
                            ACCESS_TOKEN_SECURE,
                            response);
                })
                .then(Mono.fromRunnable(() -> {
                    try {
                        log.info("send request to /chat");
                        response.sendRedirect("/chat");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }));
    }

    public Mono<String> refreshAccessToken(String refreshTokenJson, HttpServletResponse response) {
        if (refreshTokenJson == null || refreshTokenJson.isEmpty()) {
            return Mono.error(new RuntimeException("Refresh token is missing"));
        }

        String clientId = "client";
        String clientSecret = "clientSecret";
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));

        JSONObject jsonRefToken = new JSONObject(refreshTokenJson);
        String refreshToken = jsonRefToken.getString("refToken");


        log.info("token service refresh method calls");
        return webClient.post()
                .uri("/oauth2/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + encodedAuth)
                .bodyValue("grant_type=refresh_token&refresh_token=" + refreshToken)
                .retrieve()
                .bodyToMono(String.class)
                .doOnError(e -> log.error("Ошибка при обновлении токена: {}", e.getMessage()))
                .onErrorResume(e -> {
                    log.error("Error occurred during token refresh: {}", e.getMessage());
                    return Mono.error(e);
                })
                .doOnNext(jsonResponse -> {
                    log.info("Received JSON response: {}", jsonResponse);
                    if (jsonResponse == null || jsonResponse.isEmpty()) {
                        throw new RuntimeException("Received empty response from server");
                    }
                })
                .flatMap(jsonResponse -> {
                    log.info("flatMap now");
                    JSONObject jsonObject = new JSONObject(jsonResponse);
                    String accessToken = jsonObject.getString("access_token");

                    log.info("new JWT: {}", accessToken);

                    createNewCookie(ACCESS_TOKEN_NAME,
                            accessToken,
                            ACCESS_TOKEN_HTTP_ONLY,
                            ACCESS_TOKEN_PATH,
                            ACCESS_TOKEN_EXPIRY,
                            ACCESS_TOKEN_SECURE,
                            response);

                    log.info("Mono just : ");
                    return Mono.just("{\"access_token\":\"" + accessToken + "\"}");
                });
    }

    public static void createNewCookie(String name,
                                       String value,
                                       boolean httpOnly,
                                       String path,
                                       int expiry,
                                       boolean secure,
                                       HttpServletResponse response) {

        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setPath(path);
        cookie.setMaxAge(expiry);
        cookie.setSecure(secure);

        response.addCookie(cookie);
    }
}
