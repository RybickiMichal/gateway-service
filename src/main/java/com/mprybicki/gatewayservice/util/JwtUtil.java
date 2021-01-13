package com.mprybicki.gatewayservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.function.Function;

@Slf4j
public class JwtUtil {

    //TODO move config
    private String secretKey = "secret";

    public Boolean isTokenExpired(String token) {
        Date expirationDate = extractExpiration(token);
        log.info("expiration Date: " + expirationDate.toString());
        return expirationDate.before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

}