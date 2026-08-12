package net.hugmesh.forumbff.forum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.config.SecurityConfig;
import net.hugmesh.forumbff.web.ApiExceptionHandler;

import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * VN-profile surface contract + gating (reactive @WebFluxTest). The REAL
 * {@link VnProfileService} is imported over a mocked {@link ForumVnProfileRepository}
 * so the stories under test are the service-level contract, not mock echoes:
 *
 * <ul>
 *   <li>ANY authenticated principal (plain ROLE_USER, no ROLE_FORUM) uses the surface;
 *       an anonymous caller is 401;</li>
 *   <li>{@code GET /me} NEVER 404s — a subject with no row gets the synthesized
 *       defaults ({@code voiceboxStyle: "classic"}, everything else null);</li>
 *   <li>{@code PUT /me} keys on the JWT {@code sub} ONLY — a smuggled body
 *       {@code "subject"} is ignored;</li>
 *   <li>the pinned validation contract rejects with 400: bad hex accent, off-origin /
 *       wrong-prefix / traversal {@code characterImgRef}, bad style values, and an
 *       empty or &gt;50-subject lookup;</li>
 *   <li>the lookup DEDUPS before querying and omits subjects with no row.</li>
 * </ul>
 */
@WebFluxTest(controllers = VnProfileController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class, VnProfileService.class})
class VnProfileControllerTest {

    // Spring Security 7: mockJwt()'s SecurityContext is only honoured when the
    // springSecurity() configurer's MutatorFilter is in the chain (see ForumControllerTest).
    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean ForumVnProfileRepository profiles;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    /** A plain authenticated user — deliberately NO ROLE_FORUM: the VN surface serves
     *  any logged-in reader. Subject pinned to {@code sub-me}. */
    private WebTestClient asUser() {
        return web.mutateWith(mockJwt()
                .jwt(jwt -> jwt.subject("sub-me"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static ForumVnProfile row(String subject, String sticker, String img,
                                      String vbStyle, String vbAccent, String voice) {
        return new ForumVnProfile(subject, sticker, img, vbStyle, vbAccent, voice,
                Instant.parse("2026-07-15T00:00:00Z"), "default");
    }

    // ── gating ──────────────────────────────────────────────────────────

    @Test
    void anonymous_isUnauthorized_onAllThreeEndpoints() {
        web.get().uri("/bff/forum/vn-profiles/me").exchange().expectStatus().isUnauthorized();
        web.put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\"}")
                .exchange().expectStatus().isUnauthorized();
        web.post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[\"sub-a\"]}")
                .exchange().expectStatus().isUnauthorized();
    }

    // ── GET /me ─────────────────────────────────────────────────────────

    @Test
    // The NEVER-404 contract: no forum_vn_profile row -> synthesized defaults, 200.
    void me_synthesizesDefaults_whenNoRowExists() {
        when(profiles.findBySubject(eq("sub-me"), any())).thenReturn(Mono.empty());
        asUser().get().uri("/bff/forum/vn-profiles/me").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.subject").isEqualTo("sub-me")
                .jsonPath("$.voiceboxStyle").isEqualTo("classic")
                .jsonPath("$.stickerSlug").isEmpty()
                .jsonPath("$.characterImgRef").isEmpty()
                .jsonPath("$.voiceboxAccent").isEmpty()
                .jsonPath("$.voiceStyle").isEmpty();
    }

    @Test
    void me_returnsStoredProfile() {
        when(profiles.findBySubject(eq("sub-me"), any())).thenReturn(Mono.just(
                row("sub-me", "dragon", "/bff/user/media/img-1.png", "retro", "#aa11ff", "robot")));
        asUser().get().uri("/bff/forum/vn-profiles/me").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.subject").isEqualTo("sub-me")
                .jsonPath("$.stickerSlug").isEqualTo("dragon")
                .jsonPath("$.characterImgRef").isEqualTo("/bff/user/media/img-1.png")
                .jsonPath("$.voiceboxStyle").isEqualTo("retro")
                .jsonPath("$.voiceboxAccent").isEqualTo("#aa11ff")
                .jsonPath("$.voiceStyle").isEqualTo("robot");
    }

    // ── PUT /me ─────────────────────────────────────────────────────────

    @Test
    // SUBJECT-FROM-JWT: the body smuggles "subject":"sub-victim"; the write MUST key on
    // the JWT sub (sub-me) and the smuggled field is dropped (ignoreUnknown).
    void putMe_subjectAlwaysFromJwt_neverFromBody() {
        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", "dragon", null, "glass", "#00ff00", null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\":\"sub-victim\",\"stickerSlug\":\"dragon\","
                        + "\"voiceboxStyle\":\"glass\",\"voiceboxAccent\":\"#00ff00\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.subject").isEqualTo("sub-me")
                .jsonPath("$.voiceboxStyle").isEqualTo("glass");
        verify(profiles).upsert(eq("sub-me"), eq("dragon"), eq(null), eq("glass"),
                eq("#00ff00"), eq(null), any());
        verify(profiles, never()).upsert(eq("sub-victim"), any(), any(), any(), any(), any(), any());
    }

    @Test
    void putMe_400_onBadHexAccent() {
        // Uppercase hex is OUTSIDE the pinned ^#[0-9a-f]{6}$ contract.
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"voiceboxAccent\":\"#FF0000\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.voiceboxAccent").exists();
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"voiceboxAccent\":\"#12345g\"}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    // The <img src> allowlist: an absolute off-origin URL must never persist.
    void putMe_400_onOffOriginCharacterImgRef() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\","
                        + "\"characterImgRef\":\"https://evil.example/steal.png\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.characterImgRef").exists();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    // Same-origin but WRONG PREFIX (not /bff/user/) is still outside the allowlist.
    void putMe_400_onWrongPrefixCharacterImgRef() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"characterImgRef\":\"/bff/forum/avatar.png\"}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    // Path traversal inside the allowed prefix is rejected (the (?!.*\.\.) guard).
    void putMe_400_onTraversalCharacterImgRef() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\","
                        + "\"characterImgRef\":\"/bff/user/../admin/secret.png\"}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void putMe_400_onUnknownVoiceboxStyle() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"sparkle\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.voiceboxStyle").exists();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void putMe_400_onMissingVoiceboxStyle() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"stickerSlug\":\"dragon\"}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void putMe_400_onBadStickerSlug() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"stickerSlug\":\"NOT A SLUG!\"}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void putMe_400_onUnknownVoiceStyle() {
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"voiceStyle\":\"operatic\"}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).upsert(anyString(), any(), any(), any(), any(), any(), any());
    }

    @Test
    // Optional fields may be null/absent — only voiceboxStyle is required.
    void putMe_allowsMinimalBody() {
        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", null, null, "paper", null, null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"paper\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.voiceboxStyle").isEqualTo("paper");
        verify(profiles).upsert(eq("sub-me"), eq(null), eq(null), eq("paper"), eq(null), eq(null), any());
    }

    // ── POST /lookup ────────────────────────────────────────────────────

    @Test
    // Subjects with no row are simply ABSENT from the map (never null, never 404).
    void lookup_returnsOnlyExistingSubjects() {
        when(profiles.findBySubjects(anyCollection(), any())).thenReturn(Flux.just(
                row("sub-a", "cat", null, "neon", "#123abc", "warm")));
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[\"sub-a\",\"sub-missing\"]}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.profiles['sub-a'].stickerSlug").isEqualTo("cat")
                .jsonPath("$.profiles['sub-a'].voiceboxStyle").isEqualTo("neon")
                .jsonPath("$.profiles['sub-a'].voiceboxAccent").isEqualTo("#123abc")
                .jsonPath("$.profiles['sub-missing']").doesNotExist();
    }

    @Test
    // The lookup DEDUPS the requested subjects before querying.
    @SuppressWarnings("unchecked")
    void lookup_dedupsSubjectsBeforeQuerying() {
        when(profiles.findBySubjects(anyCollection(), any())).thenReturn(Flux.empty());
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[\"sub-a\",\"sub-a\",\"sub-b\",\"sub-a\"]}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.profiles").isEmpty();
        ArgumentCaptor<Collection<String>> captor = ArgumentCaptor.forClass(Collection.class);
        verify(profiles).findBySubjects(captor.capture(), any());
        assertThat(captor.getValue()).containsExactly("sub-a", "sub-b");
    }

    @Test
    void lookup_400_onEmptySubjects() {
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[]}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.subjects").exists();
        verify(profiles, never()).findBySubjects(anyCollection(), any());
    }

    @Test
    void lookup_400_onMissingSubjects() {
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).findBySubjects(anyCollection(), any());
    }

    @Test
    // OVERSIZED: 51 subjects breaches the 1..50 pinned cap -> 400, repo never queried.
    void lookup_400_onOversizedSubjectList() {
        String subjects = IntStream.rangeClosed(1, 51)
                .mapToObj(i -> "\"sub-" + i + "\"")
                .collect(Collectors.joining(","));
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[" + subjects + "]}")
                .exchange().expectStatus().isBadRequest();
        verify(profiles, never()).findBySubjects(anyCollection(), any());
    }

    @Test
    // Exactly 50 (the boundary) is ACCEPTED.
    void lookup_allows50Subjects() {
        when(profiles.findBySubjects(anyCollection(), any())).thenReturn(Flux.empty());
        String subjects = IntStream.rangeClosed(1, 50)
                .mapToObj(i -> "\"sub-" + i + "\"")
                .collect(Collectors.joining(","));
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[" + subjects + "]}")
                .exchange().expectStatus().isOk();
    }
}
