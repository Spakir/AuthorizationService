package org.example.authorizationservice.controller;

import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.dto.UserDto;
import org.example.authorizationservice.service.CustomUserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class AuthorizeController {

    private final CustomUserDetailsService userDetailsService;

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register";
    }

    @GetMapping("/index")
    public String showIndexPage(){
        return "index";
    }

    @GetMapping("hello")
    public String getHelloPage(){
        return "hello";
    }
    @GetMapping("chat")
    public String getChat(){
        return "chat";
    }

    @PostMapping("/register")
    public String registrationUser(@ModelAttribute UserDto userDto) {
        userDetailsService.saveUser(userDto);
        return "redirect:/login";
    }
}
