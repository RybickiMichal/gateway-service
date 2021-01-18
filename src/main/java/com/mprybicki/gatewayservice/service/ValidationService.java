package com.mprybicki.gatewayservice.service;

import com.mprybicki.gatewayservice.util.JwtUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
@Slf4j
public class ValidationService {

    JwtUtil jwtUtil;

    public boolean isRequestNotContainAuthorizationHeader(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }

    public boolean isRequestNotContainProperToken(ServerHttpRequest request, String token, String role, String path) {
        return !jwtUtil.containsClaim(token, role)
                && request.getURI().getPath().contains(path);
    }

    public boolean isAuthorizationHeaderNotValid(String authorizationHeader) {
        String token = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
        } else {
            log.error("Invalid header: " + authorizationHeader);
            return false;
        }
        return jwtUtil.isTokenExpired(token);
    }
}
