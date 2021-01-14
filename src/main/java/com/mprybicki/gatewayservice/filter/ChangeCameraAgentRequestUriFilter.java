package com.mprybicki.gatewayservice.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.factory.AbstractChangeRequestUriGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
@Slf4j
public class ChangeCameraAgentRequestUriFilter extends AbstractChangeRequestUriGatewayFilterFactory<ChangeCameraAgentRequestUriFilter.Config> {

    public ChangeCameraAgentRequestUriFilter() {
        super(ChangeCameraAgentRequestUriFilter.Config.class);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList(NAME_KEY);
    }

    //TODO this should be available only for user with camera-service role. Also header validation is needed
    @Override
    protected Optional<URI> determineRequestUri(ServerWebExchange exchange,
                                                Config config) {
        String requestUrl = exchange.getRequest().getHeaders().getFirst("Target");
        return Optional.ofNullable(requestUrl).map(url -> {
            try {
                return new URL(url).toURI();
            } catch (MalformedURLException | URISyntaxException e) {
                log.error("Request url is invalid : url={}, error={}", requestUrl,
                        e.getMessage());
                return null;
            }
        });
    }

    public static class Config {

    }
}