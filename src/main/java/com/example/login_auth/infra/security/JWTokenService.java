package com.example.login_auth.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.login_auth.domain.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class JWTokenService {

    // this is the server specific secret key, with the key its certain that this server sent the valid token to the user
    @Value("$api.security.token.secret")
    private String secretKey;

    public Instant createExpiration(){
        // Two hours with brazil timezone of -3
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

    public String generateToken(User user) {
        try {
            return JWT.create()
                      .withIssuer("login-auth")     // Which API is emitting this token, in this case its this api itself, can be another
                      .withSubject(user.getEmail()) // Who is receiving this token, saves the user email
                      .withExpiresAt(this.createExpiration())
                      .sign(Algorithm.HMAC256(secretKey));

        } catch (JWTCreationException e) {
            throw new RuntimeException("Error while trying to authenticate");
        }
    }

    public String validateToken(String token) {
        try {
            return JWT.require(Algorithm.HMAC256(secretKey))
                    .withIssuer("login-auth")
                    .build()
                    .verify(token)
                    .getSubject(); //Gets the genereted above value from token, in this case was the user email
        } catch (JWTVerificationException e) {
            return null;
        }
    }
}
