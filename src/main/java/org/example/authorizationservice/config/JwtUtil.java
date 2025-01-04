package org.example.authorizationservice.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.example.authorizationservice.dto.UserDto;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

@Component
public class JwtUtil {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final long EXPIRATION_TIME = 1000 * 60 * 10; // 10 минут

    public JwtUtil() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    public String generateToken(UserDto user) {
        String username = user.getUsername();
        String roles = user.getRoles().toString();

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256,privateKey)
                .compact();
    }

    public RSAPublicKey getPublicKey() {
        return publicKey; // Метод для получения публичного ключа
    }

}
