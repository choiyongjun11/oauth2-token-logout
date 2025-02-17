package com.springboot.oauth2_jwt.auth.service;

import com.springboot.exception.BusinessLogicException;
import com.springboot.oauth2_jwt.jwt.JwtTokenizer;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuthService {
    private final JwtTokenizer jwtTokenizer;

    public AuthService(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }

    public void logout(String username) {
        boolean isDeleted =
                jwtTokenizer.deleteRegisterToken(username);
        if (!isDeleted) throw new RuntimeException();

    }
}
