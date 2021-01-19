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
public class RegistrationSensorRoleFilter extends AbstractGatewayFilterFactory<RegistrationSensorRoleFilter.Config> {

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    ValidationService validationService;

    @Autowired
    ErrorService errorService;

    public RegistrationSensorRoleFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();
            String authorizationHeader = request.getHeaders().get("Authorization").get(0);
            String token = authorizationHeader.substring(7);

            if (validationService.isRequestNotContainProperToken(request, token, "CameraRegistrationRole", "/camera/")) {
                return errorService.onError(exchange, HttpStatus.FORBIDDEN);
            } else if (validationService.isRequestNotContainProperToken(request, token, "RFSensorRegistrationRole", "/rf-sensor/")) {
                return errorService.onError(exchange, HttpStatus.FORBIDDEN);
            }

            return chain.filter(exchange.mutate().request(request).build());
        };
    }

    public static class Config {}
}