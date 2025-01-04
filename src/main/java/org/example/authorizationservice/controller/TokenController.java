package org.example.authorizationservice.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.service.TokenService;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @GetMapping("/success")
    public Mono<String> getToken(@RequestParam("code") String code, HttpServletResponse response) {
        return tokenService.exchangeAuthorizationCodeForToken(code)
                .doOnNext(jsonResponse -> {
                    JSONObject jsonObject = new JSONObject(jsonResponse);
                    String accessToken = jsonObject.getString("access_token");

                    Cookie cookie = new Cookie("JWT", accessToken);
                    cookie.setHttpOnly(true);
                    cookie.setPath("/");
                    cookie.setMaxAge(3600);
                    cookie.setSecure(false);

                    response.addCookie(cookie);
                })
                .then(Mono.just("Token successfully stored in cookie"));
    }
}
