package com.iot.iotgtw.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter());
        // Require authentication for all requests
        http.authorizeExchange()
                .pathMatchers("/kc/**").permitAll()
                .anyExchange().authenticated();
        // Allow showing pages within a frame
//        http.headers().frameOptions().sameOrigin();

        return http.build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        // Convert realm_access.roles claims to granted authorities, for use in access decisions
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }


    class JwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
        private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter
                = new JwtGrantedAuthoritiesConverter();

        public JwtAuthenticationConverter() {
        }

        public final Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
            Collection<GrantedAuthority> authorities = this.extractAuthorities(jwt);
            return Mono.create(callback -> callback.success(new JwtAuthenticationToken(jwt, authorities)));
        }

        protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
            return (Collection)this.jwtGrantedAuthoritiesConverter.convert(jwt);
        }

        public void setJwtGrantedAuthoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
            Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
            this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
        }
    }

    class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
            return ((List<String>) realmAccess.get("roles")).stream()
                    .map(roleName -> "ROLE_" + roleName)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
    }

}