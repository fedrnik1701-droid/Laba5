package org.example.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.example.dto.RegisterRequest;
import org.example.service.SessionService;
import org.example.service.SessionService.TokenPair;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final SessionService sessions;

    public record LoginRequest(@NotBlank String username, @NotBlank String password,
                               @Size(max = 255) String deviceId) {}
    public record RefreshRequest(@NotBlank String refreshToken) {}

    @PostMapping("/login")
    public TokenPair login(@Valid @RequestBody LoginRequest request) {
        return sessions.login(request.username(), request.password(), request.deviceId());
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenPair register(@Valid @RequestBody RegisterRequest request) {
        return sessions.register(request);
    }

    @PostMapping("/refresh")
    public TokenPair refresh(@Valid @RequestBody RefreshRequest request) {
        return sessions.refresh(request.refreshToken())
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
    }
}
