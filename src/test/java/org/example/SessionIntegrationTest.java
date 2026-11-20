package org.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.entity.SessionStatus;
import org.example.entity.UserSession;
import org.example.repository.UserSessionRepository;
import org.example.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = "spring.jpa.show-sql=false")
@AutoConfigureMockMvc
class SessionIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired UserSessionRepository sessions;
    @Autowired JwtService jwt;

    @Test
    void rotationAndReplay() throws Exception {
        JsonNode first = login();
        String access = token(first, "accessToken"), refresh = token(first, "refreshToken");
        UserSession original = session(refresh);
        assertEquals(SessionStatus.ACTIVE, original.getStatus());
        assertEquals(jwt.validateAccess(access).getExpiresAt(), original.getAccessTokenExpiry());
        assertEquals(jwt.validateRefresh(refresh).getExpiresAt(), original.getRefreshTokenExpiry());
        mvc.perform(get("/api/books").header("Authorization", "Bearer " + access)).andExpect(status().isOk());
        mvc.perform(get("/api/books").header("Authorization", "Bearer " + refresh)).andExpect(status().isUnauthorized());
        mvc.perform(post("/auth/refresh").contentType("application/json").content(refreshBody(access)))
                .andExpect(status().isUnauthorized());
        long count = sessions.count();
        JsonNode next = json.readTree(mvc.perform(post("/auth/refresh").contentType("application/json")
                        .content(refreshBody(refresh))).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        String nextRefresh = token(next, "refreshToken");
        assertNotEquals(access, token(next, "accessToken"));
        assertNotEquals(refresh, nextRefresh);
        assertEquals(SessionStatus.USED, session(refresh).getStatus());
        assertEquals(SessionStatus.ACTIVE, session(nextRefresh).getStatus());
        assertEquals("test-device", session(nextRefresh).getDeviceId());
        assertEquals(401, refreshStatus(refresh));
        assertEquals(401, refreshStatus(refresh));
        assertEquals(SessionStatus.REVOKED, session(refresh).getStatus());
        assertEquals(SessionStatus.ACTIVE, session(nextRefresh).getStatus());
        assertEquals(count + 1, sessions.count());
    }

    @Test
    void concurrentRefreshIssuesOnlyOnePair() throws Exception {
        String refresh = token(login(), "refreshToken");
        long count = sessions.count();
        var pool = Executors.newFixedThreadPool(2);
        var start = new CyclicBarrier(2);
        try {
            var first = pool.submit(() -> { start.await(10, TimeUnit.SECONDS); return refreshStatus(refresh); });
            var second = pool.submit(() -> { start.await(10, TimeUnit.SECONDS); return refreshStatus(refresh); });
            int a = first.get(10, TimeUnit.SECONDS), b = second.get(10, TimeUnit.SECONDS);
            assertTrue((a == 200 && b == 401) || (a == 401 && b == 200));
            assertEquals(count + 1, sessions.count());
            assertEquals(SessionStatus.REVOKED, session(refresh).getStatus());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void registrationIssuesReaderTokensAndValidatesInput() throws Exception {
        String request = """
                {"fullName":"Test","email":"new@example.com","password":"Reader123!","role":"LIBRARIAN"}
                """;
        JsonNode pair = json.readTree(mvc.perform(post("/auth/register").contentType("application/json").content(request))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString());
        String access = token(pair, "accessToken");
        assertEquals(SessionStatus.ACTIVE, session(token(pair, "refreshToken")).getStatus());
        mvc.perform(get("/api/readers").header("Authorization", "Bearer " + access)).andExpect(status().isForbidden());
        mvc.perform(post("/auth/register").contentType("application/json").content(request)).andExpect(status().isConflict());
        mvc.perform(post("/auth/register").contentType("application/json").content(request.replace("Reader123!", "weak")))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/auth/refresh").contentType("application/json").content("{}")).andExpect(status().isBadRequest());
        mvc.perform(post("/auth/login").contentType("application/json")
                        .content("{\"username\":\"alex@example.com\",\"password\":\"Reader123!\"}"))
                .andExpect(status().isUnauthorized());
        assertEquals(401, refreshStatus("broken-token"));
    }

    private JsonNode login() throws Exception {
        return json.readTree(mvc.perform(post("/auth/login").contentType("application/json")
                        .content("{\"username\":\"librarian@example.com\",\"password\":\"Librarian123!\",\"deviceId\":\"test-device\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private int refreshStatus(String refresh) throws Exception {
        return mvc.perform(post("/auth/refresh").contentType("application/json").content(refreshBody(refresh)))
                .andReturn().getResponse().getStatus();
    }

    private String refreshBody(String refresh) throws Exception {
        return json.writeValueAsString(Map.of("refreshToken", refresh));
    }

    private String token(JsonNode pair, String key) {
        return pair.get(key).asText();
    }

    private UserSession session(String refresh) {
        return sessions.findAll().stream().filter(s -> s.getRefreshToken().equals(refresh)).findFirst().orElseThrow();
    }
}
