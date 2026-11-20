package org.example.service;

import lombok.RequiredArgsConstructor;
import org.example.dto.RegisterRequest;
import org.example.entity.Reader;
import org.example.entity.SessionStatus;
import org.example.entity.UserSession;
import org.example.repository.ReaderRepository;
import org.example.repository.UserSessionRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SessionService {
    private final ReaderRepository readers;
    private final UserSessionRepository sessions;
    private final RegistrationService registration;
    private final PasswordEncoder encoder;
    private final JwtService tokens;

    public record TokenPair(String accessToken, String refreshToken) {}

    @Transactional
    public TokenPair login(String username, String password, String deviceId) {
        Reader reader = readers.findByEmailIgnoreCase(username)
                .filter(r -> Boolean.TRUE.equals(r.getActive()) && r.getPassword() != null)
                .filter(r -> encoder.matches(password, r.getPassword()))
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        return issue(reader, deviceId);
    }

    @Transactional
    public TokenPair register(RegisterRequest request) {
        return issue(registration.register(request), request.deviceId());
    }

    @Transactional
    public Optional<TokenPair> refresh(String refreshToken) {
        Jwt jwt;
        try {
            jwt = tokens.validateRefresh(refreshToken);
        } catch (JwtException ex) {
            return Optional.empty();
        }
        UserSession session = sessions.findByRefreshToken(refreshToken).orElse(null);
        if (session == null || !session.getUsername().equals(jwt.getSubject())
                || !session.getRefreshTokenExpiry().isAfter(Instant.now())) {
            return Optional.empty();
        }
        if (session.getStatus() == SessionStatus.USED) {
            session.revoke();
            return Optional.empty(); // Обычный возврат сохраняет REVOKED до отправки 401.
        }
        if (session.getStatus() != SessionStatus.ACTIVE) return Optional.empty();
        Reader reader = readers.findById(tokens.readerId(jwt))
                .filter(r -> Boolean.TRUE.equals(r.getActive()) && jwt.getSubject().equals(r.getEmail()))
                .orElse(null);
        if (reader == null) return Optional.empty();
        session.markUsed();
        return Optional.of(issue(reader, session.getDeviceId()));
    }

    private TokenPair issue(Reader reader, String deviceId) {
        Jwt access = tokens.createAccess(reader);
        Jwt refresh = tokens.createRefresh(reader);
        sessions.save(new UserSession(reader.getEmail(), deviceId, access.getTokenValue(), refresh.getTokenValue(),
                access.getExpiresAt(), refresh.getExpiresAt()));
        return new TokenPair(access.getTokenValue(), refresh.getTokenValue());
    }
}
