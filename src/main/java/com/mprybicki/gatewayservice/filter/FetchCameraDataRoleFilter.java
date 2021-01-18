package com.mprybicki.gatewayservice.filter;

import com.mprybicki.gatewayservice.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractChangeRequestUriGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
@Slf4j
public class FetchCameraDataRoleFilter extends AbstractGatewayFilterFactory<FetchCameraDataRoleFilter.Config> {

    @Autowired
    JwtUtil jwtUtil;

    public FetchCameraDataRoleFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(FetchCameraDataRoleFilter.Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            //TODO  walidacje do osobnej klasy
            if (!request.getHeaders().containsKey("Authorization")) {
                return this.onError(exchange, "No Authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get("Authorization").get(0);
            String token = authorizationHeader.substring(7);
            if (!jwtUtil.containsClaim(token , "FetchCameraDataRole")
                    && request.getURI().getPath().contains("/position-data")) {
                return this.onError(exchange, "User without fetch camera data role", HttpStatus.FORBIDDEN);
            }

            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate().
                    header("secret", RandomStringUtils.random(10)).
                    build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    public static class Config {

    }
}
