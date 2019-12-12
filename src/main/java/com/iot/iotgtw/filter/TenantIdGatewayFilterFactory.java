package com.iot.iotgtw.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
public class TenantIdGatewayFilterFactory extends AbstractGatewayFilterFactory {

    private static final String X_TENANT_ID = "X-TenantId";

    public GatewayFilter apply() {
        return apply((Object) null);
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(principal -> principal instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(jwtAuthenticationToken -> withTenantId(exchange, jwtAuthenticationToken))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    private ServerWebExchange withTenantId(ServerWebExchange exchange,
                                           JwtAuthenticationToken jwtAuthenticationToken) {
        Jwt jwt = jwtAuthenticationToken.getToken();

        String tenantId = jwt.getClaimAsString("tenantId");
        String userId = jwt.getClaimAsString("sub");

        return exchange.mutate()
                .request(r -> r.headers(
                        headers -> headers.set(X_TENANT_ID, tenantId != null ? tenantId : userId)))
                .build();
    }

}
