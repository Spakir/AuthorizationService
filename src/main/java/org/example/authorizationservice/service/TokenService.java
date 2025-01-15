package org.example.authorizationservice.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
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

    private final String REFRESH_TOKEN_NAME = "refreshToken";
    private final String REFRESH_TOKEN_PATH = "/";
    private final int REFRESH_TOKEN_EXPIRY = 3600 * 24 * 30;
    private final boolean REFRESH_TOKEN_HTTP_ONLY = false;
    private final boolean REFRESH_TOKEN_SECURE = false;

    @Value("${spring.security.oauth2.client.registration.custom.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.custom.client-secret}")
    private String clientSecret;

    public TokenService(WebClient.Builder web) {
        this.webClient = web.baseUrl("http://localhost:8080").build();
    }

    public Mono<String> exchangeAuthorizationCodeForToken(String code, HttpServletResponse response) {
        String encodedAuth = getEncodedAuthenticationForClient();

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
                    String refreshToken = jsonObject.getString("refresh_token");

                    log.info("refresh token : {}", refreshToken);

                    createNewCookie(REFRESH_TOKEN_NAME,
                            refreshToken, REFRESH_TOKEN_HTTP_ONLY,
                            REFRESH_TOKEN_PATH,
                            REFRESH_TOKEN_EXPIRY,
                            REFRESH_TOKEN_SECURE,
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

        String encodedAuth = getEncodedAuthenticationForClient();
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

    public void createNewCookie(String name,
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

    public String getEncodedAuthenticationForClient() {
        String auth = String.format("%s:%s", clientId, clientSecret);
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));

        return encodedAuth;
    }
}
