package com.springboot.oauth2_jwt.auth.controller;

import com.springboot.oauth2_jwt.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authservice;

    public AuthController(AuthService authservice) {
        this.authservice = authservice;
    }

    @PostMapping("/logout") //login 상태가 아니면 null
    public ResponseEntity postLogout(Authentication authentication) {
        String username = authentication.getName();

        authservice.logout(username);


        return new ResponseEntity(HttpStatus.OK);
    }
}
