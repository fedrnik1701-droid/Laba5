package org.example.service;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.example.entity.Reader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service
public class JwtService {
    private final JwtEncoder encoder;
    private final JwtDecoder decoder;
    private final Duration accessTtl;
    private final Duration refreshTtl;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.access-ttl}") String accessTtl,
                      @Value("${app.jwt.refresh-ttl}") String refreshTtl) throws NoSuchAlgorithmException {
        this.accessTtl = ttl(accessTtl);
        this.refreshTtl = ttl(refreshTtl);
        SecretKey key;
        if (secret.isBlank()) {
            KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
            generator.init(256);
            key = generator.generateKey();
        } else {
            byte[] bytes = Base64.getDecoder().decode(secret);
            if (bytes.length < 32) throw new IllegalArgumentException("JWT_SECRET requires at least 32 bytes");
            key = new SecretKeySpec(bytes, "HmacSHA256");
        }
        encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        var nimbus = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        nimbus.setJwtValidator(new JwtTimestampValidator(Duration.ZERO));
        decoder = nimbus;
    }

    public Jwt createAccess(Reader reader) {
        return create(reader, "access", accessTtl);
    }

    public Jwt createRefresh(Reader reader) {
        return create(reader, "refresh", refreshTtl);
    }

    public Jwt validateAccess(String token) {
        return validate(token, "access");
    }

    public Jwt validateRefresh(String token) {
        return validate(token, "refresh");
    }

    public Long readerId(Jwt jwt) {
        Object id = jwt.getClaims().get("uid");
        if (id instanceof Number number && number.longValue() > 0) return number.longValue();
        throw new BadJwtException("Invalid JWT subject");
    }

    private Jwt create(Reader reader, String type, Duration ttl) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var claims = JwtClaimsSet.builder().subject(reader.getEmail()).claim("uid", reader.getId())
                .id(UUID.randomUUID().toString()).claim("type", type)
                .issuedAt(now).expiresAt(now.plus(ttl)).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims));
    }

    private Jwt validate(String token, String type) {
        Jwt jwt = decoder.decode(token);
        if (!type.equals(jwt.getClaims().get("type")) || jwt.getSubject() == null || jwt.getSubject().isBlank()
                || jwt.getId() == null || jwt.getId().isBlank() || jwt.getIssuedAt() == null
                || jwt.getExpiresAt() == null || !jwt.getExpiresAt().isAfter(Instant.now())) {
            throw new BadJwtException("Invalid JWT claims");
        }
        readerId(jwt);
        return jwt;
    }

    private static Duration ttl(String value) {
        Duration ttl = DurationStyle.detectAndParse(value);
        if (ttl.toSeconds() < 1) throw new IllegalArgumentException("JWT lifetime must be at least one second");
        return Duration.ofSeconds(ttl.toSeconds());
    }
}
