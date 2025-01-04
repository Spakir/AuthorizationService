package org.example.authorizationservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthorizeRestController {

    @GetMapping("/codesuccess")
    public String getCode(@RequestParam("code") String code){
        return code;
    }
}
