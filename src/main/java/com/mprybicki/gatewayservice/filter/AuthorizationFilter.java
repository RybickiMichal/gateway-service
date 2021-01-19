package com.mprybicki.gatewayservice.filter;

import com.mprybicki.gatewayservice.service.ErrorService;
import com.mprybicki.gatewayservice.service.ValidationService;
import com.mprybicki.gatewayservice.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    ValidationService validationService;

    @Autowired
    ErrorService errorService;

    public AuthorizationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if (validationService.isRequestNotContainAuthorizationHeader(request)) {
                return errorService.onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get("Authorization").get(0);
            if (validationService.isAuthorizationHeaderNotValid(authorizationHeader)) {
                return errorService.onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange.mutate().request(request).build());
        };
    }

    public static class Config {}
}
