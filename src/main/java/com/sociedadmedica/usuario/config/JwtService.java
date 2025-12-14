package com.sociedadmedica.usuario.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    // ✅ Si falta en properties, usa este default (32+ chars)
    @Value("${jwt.secret:MI_SECRETO_SUPER_LARGO_DE_32_CARACTERES_O_MAS_1234567890}")
    private String secret;

    // ✅ Si falta en properties, default 24h
    @Value("${jwt.expiration:86400000}")
    private long jwtExpirationMs;

    @PostConstruct
    public void validateConfig() {
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalStateException("jwt.secret está vacío. Configúralo en application.properties");
        }
        if (secret.trim().length() < 32) {
            throw new IllegalStateException("jwt.secret debe tener al menos 32 caracteres para HS256");
        }
        if (jwtExpirationMs <= 0) {
            throw new IllegalStateException("jwt.expiration debe ser mayor a 0 (milisegundos)");
        }
    }

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.trim().getBytes(StandardCharsets.UTF_8));
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return buildToken(claims, userDetails.getUsername());
    }

    private String buildToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
