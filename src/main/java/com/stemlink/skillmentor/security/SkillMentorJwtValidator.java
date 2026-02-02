package com.stemlink.skillmentor.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.List;

@Slf4j
public class SkillMentorJwtValidator implements TokenValidator {

//    @Value("${jwt.secret:my-secret-key-must-be-at-least-32-characters-long-for-HS256}")
    private  final String secretKey ;

    public SkillMentorJwtValidator(String secretKey) {
        this.secretKey = secretKey;
    }

    private SecretKey getSigningKey() {

        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public String extractUsername(String token) {

        return getClaims(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {

        return (List<String>) getClaims(token).get("roles", List.class);
    }

    @Override
    public String extractFirstName(String token) {
        return "";
    }

    @Override
    public String extractLastName(String token) {
        return "";
    }

    @Override
    public String extractEmail(String token) {
        return "";
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            System.err.println(e.getMessage());
            // Token validation failed - could be invalid signature, expired, or missing kid header
            return false;
        }
    }

    @Override
    public String extractUserId(String token) {
        return null;
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}