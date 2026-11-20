package org.example.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
@Getter
@NoArgsConstructor(access = lombok.AccessLevel.PROTECTED)
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false)
    private String username;
    private String deviceId;
    @Column(nullable = false, columnDefinition = "TEXT")
    private String accessToken;
    @Column(nullable = false, unique = true, columnDefinition = "TEXT")
    private String refreshToken;
    @Column(nullable = false)
    private Instant accessTokenExpiry;
    @Column(nullable = false)
    private Instant refreshTokenExpiry;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SessionStatus status = SessionStatus.ACTIVE;

    public UserSession(String username, String deviceId, String accessToken, String refreshToken,
                       Instant accessTokenExpiry, Instant refreshTokenExpiry) {
        this.username = username;
        this.deviceId = deviceId;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.accessTokenExpiry = accessTokenExpiry;
        this.refreshTokenExpiry = refreshTokenExpiry;
    }

    public void markUsed() {
        status = SessionStatus.USED;
    }

    public void revoke() {
        status = SessionStatus.REVOKED;
    }
}
