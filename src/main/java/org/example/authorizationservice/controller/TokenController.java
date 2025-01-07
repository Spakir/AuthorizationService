package org.example.authorizationservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.service.TokenService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @GetMapping("/success")
    public Mono<Void> getToken(@RequestParam("code") String code, HttpServletResponse response) {
        return tokenService.exchangeAuthorizationCodeForToken(code,response).then();
    }
}
