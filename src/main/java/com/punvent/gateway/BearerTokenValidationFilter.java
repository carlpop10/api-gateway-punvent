package com.punvent.gateway;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class BearerTokenValidationFilter implements GlobalFilter, Ordered {
    private final ObjectMapper mapper;
    private final byte[] secret;
    private final String issuer;
    private final String audience;

    public BearerTokenValidationFilter(ObjectMapper mapper,
            @Value("${app.auth.jwt-secret:change-this-development-jwt-secret-at-least-32-bytes}") String secret,
            @Value("${app.auth.issuer:punvent-service}") String issuer,
            @Value("${app.auth.audience:punvent-api}") String audience) {
        this.mapper = mapper; this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.issuer = issuer; this.audience = audience;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) return chain.filter(exchange);
        try {
            validate(authorization.substring(7).trim());
            return chain.filter(exchange);
        } catch (TokenExpiredException ex) {
            return reject(exchange, "AUTH-401-TOKEN-EXPIRED", "El token de acceso ha expirado");
        } catch (Exception ex) {
            return reject(exchange, "AUTH-401-INVALID-TOKEN", "El token de acceso no es valido");
        }
    }

    private void validate(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException();
        String signed = parts[0] + "." + parts[1];
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        if (!MessageDigest.isEqual(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)),
                Base64.getUrlDecoder().decode(parts[2]))) throw new IllegalArgumentException();
        Map<String, Object> claims = mapper.readValue(Base64.getUrlDecoder().decode(parts[1]), new TypeReference<>() {});
        if (!issuer.equals(String.valueOf(claims.get("iss"))) || !audience.equals(String.valueOf(claims.get("aud"))))
            throw new IllegalArgumentException();
        if (!Instant.now().isBefore(Instant.ofEpochSecond(((Number) claims.get("exp")).longValue())))
            throw new TokenExpiredException();
    }

    private Mono<Void> reject(ServerWebExchange exchange, String code, String description) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] json = ("{\"codeError\":\"" + code + "\",\"typeError\":\"UNAUTHORIZED\","
                + "\"descriptionError\":\"" + description + "\"}").getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(json);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Override public int getOrder() { return -100; }
    private static final class TokenExpiredException extends RuntimeException {}
}
