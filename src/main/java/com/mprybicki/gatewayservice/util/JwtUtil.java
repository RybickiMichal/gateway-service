package com.mprybicki.gatewayservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtil {

    @Value("${token.secret.key}")
    private String secretKey;

    public Boolean isTokenExpired(String token) {
        Date expirationDate = extractExpiration(token);
        log.info("Token expiration date: " + expirationDate.toString());
        return expirationDate.before(new Date());
    }

    public boolean containsClaim(String token, String claim){
        final Claims claims = extractAllClaims(token);
        return claims.containsKey(claim);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

}