package org.example.authorizationservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authorizationservice.service.TokenService;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @GetMapping("/success")
    public Mono<Void> getToken(@RequestParam("code") String code, HttpServletResponse response) {
        log.info(code);
        return tokenService.exchangeAuthorizationCodeForToken(code, response).then();
    }

    @PostMapping("/refreshToken")
    public Mono<String> refreshAccessToken(@RequestBody String refreshToken, HttpServletResponse response) {

        log.info("Refresh token calls");

        if (refreshToken == null || refreshToken.isEmpty()) {
            return Mono.error(new RuntimeException("Refresh token is missing"));
        }
        return tokenService.refreshAccessToken(refreshToken, response);
    }

}
