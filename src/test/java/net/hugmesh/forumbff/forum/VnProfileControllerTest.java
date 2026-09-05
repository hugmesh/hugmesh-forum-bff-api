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
import java.util.List;
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
 *   <li>the lookup DEDUPS before querying and omits subjects with no row;</li>
 *   <li>OWNER-BLIND {@code characterImgRef} spellings
 *       ({@link VnProfileDto#OWNER_BLIND_IMG_REFS}) are suppressed on the reader-facing
 *       lookup, while {@code GET /me} still echoes a stored one so the owner's editor
 *       can repair it; the self-avatar serve is additionally never stored
 *       ({@link VnProfileDto#UNSTORABLE_IMG_REFS}), while the legacy handle ref IS
 *       stored because it is that repair signal;</li>
 *   <li>every spelling a URL parser rewrites — dot-segments, empty segments — is
 *       refused at the charset gate, and the owner-blind comparison itself runs on the
 *       CANONICAL path, so a legacy row spelled {@code /a/./b} is still caught.</li>
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
    // CROSS-REPO CONTRACT REGRESSION (issue #3). The value hugmesh-forum-ui stores for
    // an avatar-mode VN profile is the RESOLVED serve URL of hugmesh-user-bff-api's
    // character-avatar route — /bff/user/character/avatar/{opaque-handle}/body. The
    // BARE path this UI used to store named no owner and nothing served it, so every
    // sprite rendered broken. This BFF must keep ACCEPTING the real serve URL: a
    // tightened allowlist here would silently break every sprite again, in a repo that
    // never dereferences the value and so would never notice.
    void putMe_acceptsTheRealUserBffAvatarServeUrl() {
        String ref = "/bff/user/character/avatar/3f2504e0-4f89-41d3-9a0c-0305e82c3301/body";
        // The shape constants are the pinned contract; assert the stored value matches
        // them AND that the live allowlist admits it (the two must never drift).
        assertThat(ref).matches(VnProfileDto.CANONICAL_AVATAR_REF_SHAPE);
        assertThat(ref).matches(VnProfileDto.CHARACTER_IMG_REF);
        assertThat(ref.length()).isLessThanOrEqualTo(256);

        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", null, ref, "classic", null, null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"characterImgRef\":\"" + ref + "\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.characterImgRef").isEqualTo(ref);
        // It survives the SERVICE-layer re-check too (the defence-in-depth allowlist),
        // not just bean validation — both gates have to admit a real serve URL.
        verify(profiles).upsert(eq("sub-me"), eq(null), eq(ref), eq("classic"), eq(null), eq(null), any());
    }

    @Test
    // Sibling media, same contract: the sticker serve URL of hugmesh-user-bff-api's
    // StickerController must also stay storable. DEFENSIVE pin — nothing in the trio
    // writes a sticker body URL into characterImgRef today: hugmesh-forum-ui builds the
    // sticker <img src> at render time from the separate stickerSlug field
    // (topic-detail.component.ts spriteUrl). The constraint that actually carries
    // sticker sprites is STICKER_SLUG, pinned in the shape-coverage test below.
    // The fixture uses a REAL-looking slug (underscore, short) rather than a UUID, so it
    // exercises the charset the route's own SLUG_SHAPE declares.
    void putMe_acceptsTheRealUserBffStickerServeUrl() {
        String ref = "/bff/user/character/stickers/happy_face/body";
        assertThat(ref).matches(VnProfileDto.CANONICAL_STICKER_REF_SHAPE);
        assertThat(ref).matches(VnProfileDto.CHARACTER_IMG_REF);

        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", null, ref, "classic", null, null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"characterImgRef\":\"" + ref + "\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.characterImgRef").isEqualTo(ref);
    }

    @Test
    // OWNER-BLIND REFS (the half of issue #3 that outlived the serving route).
    // "/bff/user/character/avatar" is hugmesh-user-bff-api's HANDLE endpoint: it answers
    // JSON to whoever asks, so as an <img src> it is a guaranteed broken image — and the
    // reader-facing lookup suppresses it (below). It is nevertheless STORED, on purpose:
    // it is the exact literal every pre-hugmesh-forum-ui#14 bundle sends on EVERY save,
    // and the ONLY record that this user asked for their avatar. The owner's editor
    // re-ticks "use my avatar" from it and rewrites a resolvable URL on the next save.
    // Clearing it here would flip that tick off on the next load, make re-ticking
    // impossible (each save re-clears it), and destroy the repair signal before the user
    // ever receives the new bundle — i.e. it would perform, one row at a time, exactly
    // the erasure that rules out a NULLing data migration. The reader is already safe.
    void putMe_keepsTheLegacyAvatarHandlePath_becauseItIsTheRepairSignal() {
        String handlePath = VnProfileDto.LEGACY_AVATAR_HANDLE_REF;
        // It is inside the charset allowlist: shape validation alone cannot see this.
        assertThat(handlePath).matches(VnProfileDto.CHARACTER_IMG_REF);
        assertThat(VnProfileDto.OWNER_BLIND_IMG_REFS).contains(handlePath);
        assertThat(VnProfileDto.UNSTORABLE_IMG_REFS).doesNotContain(handlePath);

        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", "cat", handlePath, "classic", null, null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"stickerSlug\":\"cat\","
                        + "\"characterImgRef\":\"" + handlePath + "\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.characterImgRef").isEqualTo(handlePath)
                .jsonPath("$.stickerSlug").isEqualTo("cat");
        // What reached the STORE is the handle path itself — the signal survives.
        verify(profiles).upsert(eq("sub-me"), eq("cat"), eq(handlePath), eq("classic"),
                eq(null), eq(null), any());
    }

    @Test
    // The other owner-blind spelling, and the worse one: /bff/user/profile/avatar/body
    // resolves its owner from jwt.getSubject(), so a post storing it renders the READER's
    // own picture beside the AUTHOR's name — a misattributed face, not a broken image.
    // Nothing in the trio writes it, which is exactly why the server has to refuse it:
    // the value is reachable with one hand-rolled PUT.
    void putMe_clearsTheOwnerScopedSelfAvatarServePath() {
        String selfServe = "/bff/user/profile/avatar/body";
        assertThat(selfServe).matches(VnProfileDto.CHARACTER_IMG_REF);
        assertThat(selfServe).doesNotMatch(VnProfileDto.CANONICAL_AVATAR_REF_SHAPE);

        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", null, null, "classic", null, null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\",\"characterImgRef\":\"" + selfServe + "\"}")
                .exchange().expectStatus().isOk();
        verify(profiles).upsert(eq("sub-me"), eq(null), eq(null), eq("classic"), eq(null), eq(null), any());
    }

    @Test
    // Trailing-slash near-misses collapse onto the same rule: "…/body/" is the same
    // owner-blind endpoint, and a rule that only matched the exact string would let the
    // one-character variant straight through.
    void putMe_clearsTheSelfAvatarServe_withATrailingSlashToo() {
        when(profiles.upsert(eq("sub-me"), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(row("sub-me", null, null, "classic", null, null)));
        asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"voiceboxStyle\":\"classic\","
                        + "\"characterImgRef\":\"/bff/user/profile/avatar/body/\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.characterImgRef").doesNotExist();
        verify(profiles).upsert(eq("sub-me"), eq(null), eq(null), eq("classic"), eq(null), eq(null), any());
    }

    @Test
    // THE BYPASS (round-2 refutation, HIGH). A set-membership test compares STRINGS; a
    // browser compares PARSED paths. "/bff/user/profile/avatar/./body" is charset-legal,
    // is not equal to any owner-blind literal, and Chromium still puts
    // "/bff/user/profile/avatar/body" on the wire — measured: it even DEDUPLICATES that
    // <img> against one spelled with the plain path. So one hand-rolled PUT was enough to
    // paint every reader's own face beside the author's name, silently, with a real 200.
    // Every spelling a URL parser rewrites is now refused at the charset gate, so it
    // cannot be stored at all.
    void putMe_refusesEverySpellingAUrlParserWouldRewrite() {
        for (String smuggled : List.of(
                "/bff/user/profile/avatar/./body",      // dot-segment -> the self serve
                "/bff/user/character/./avatar",         // dot-segment -> the handle path
                "/bff/user//profile/avatar/body",       // empty segment
                "/bff/user/profile/avatar/body/.",      // trailing dot-segment
                "/bff/user/character/avatar/../../profile/avatar/body")) { // traversal
            asUser().put().uri("/bff/forum/vn-profiles/me").contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"voiceboxStyle\":\"classic\",\"characterImgRef\":\""
                            + smuggled + "\"}")
                    .exchange().expectStatus().isBadRequest();
            assertThat(smuggled).doesNotMatch(VnProfileDto.CHARACTER_IMG_REF);
        }
        verify(profiles, never()).upsert(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    // …and the charset stays surgical: a dot INSIDE a segment is an ordinary character no
    // parser rewrites, so a filename-shaped ref must still validate. This is the assertion
    // that fails if the dot-segment rule is ever written as "reject any '.'".
    void charsetStillAcceptsADotInsideASegment() {
        assertThat("/bff/user/character/avatar/3f2504e0-4f89-41d3-9a0c-0305e82c3301/body")
                .matches(VnProfileDto.CHARACTER_IMG_REF);
        assertThat("/bff/user/character/portrait.v2.png").matches(VnProfileDto.CHARACTER_IMG_REF);
        assertThat("/bff/user/character/.hidden/body").matches(VnProfileDto.CHARACTER_IMG_REF);
        assertThat("/bff/user/character/avatar/").matches(VnProfileDto.CHARACTER_IMG_REF);
    }

    @Test
    // The REPAIR path, and the reason GET /me is deliberately not filtered: a row written
    // before the serving route existed still holds the handle path, and the owner's editor
    // (hugmesh-forum-ui vn-profile-editor.component.ts) reads it to re-tick "use my avatar"
    // and rewrite a resolvable URL on the next save. Filtering it here — or NULLing it in a
    // migration — would erase that intent and leave the user to rediscover the setting.
    void me_echoesAStoredOwnerBlindRef_soTheOwnersEditorCanRepairIt() {
        when(profiles.findBySubject(eq("sub-me"), any()))
                .thenReturn(Mono.just(row("sub-me", null, "/bff/user/character/avatar",
                        "classic", null, null)));
        asUser().get().uri("/bff/forum/vn-profiles/me").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.characterImgRef").isEqualTo("/bff/user/character/avatar");
    }

    @Test
    // …and the READER-facing projection is where the same stored row must NOT survive:
    // POST /lookup feeds the VN reader's <img src> for OTHER people's posts. Suppressing
    // it here is what repairs the already-written rows without a data migration. The
    // author's stickerSlug is left intact, so the reader falls back to their sticker
    // exactly as for a profile that never set an image.
    void lookup_suppressesAStoredOwnerBlindRef_butKeepsTheStickerFallback() {
        when(profiles.findBySubjects(anyCollection(), any())).thenReturn(Flux.just(
                row("sub-a", "cat", "/bff/user/character/avatar", "neon", null, null),
                row("sub-b", null, "/bff/user/profile/avatar/body", "classic", null, null)));
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[\"sub-a\",\"sub-b\"]}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.profiles['sub-a'].characterImgRef").doesNotExist()
                .jsonPath("$.profiles['sub-a'].stickerSlug").isEqualTo("cat")
                .jsonPath("$.profiles['sub-a'].voiceboxStyle").isEqualTo("neon")
                .jsonPath("$.profiles['sub-b'].characterImgRef").doesNotExist();
    }

    @Test
    // The suppression must be SURGICAL: a real serve URL — the whole point of the
    // cross-repo route — still reaches the reader. A rule written one segment too wide
    // (e.g. "starts with /bff/user/character/avatar") would blank every avatar sprite on
    // the platform and look exactly like the bug it was meant to fix.
    void lookup_stillServesTheRealAvatarAndStickerServeUrls() {
        String avatar = "/bff/user/character/avatar/3f2504e0-4f89-41d3-9a0c-0305e82c3301/body";
        String sticker = "/bff/user/character/stickers/happy_face/body";
        assertThat(avatar).matches(VnProfileDto.CANONICAL_AVATAR_REF_SHAPE);
        assertThat(sticker).matches(VnProfileDto.CANONICAL_STICKER_REF_SHAPE);

        when(profiles.findBySubjects(anyCollection(), any())).thenReturn(Flux.just(
                row("sub-a", null, avatar, "classic", null, null),
                row("sub-b", null, sticker, "classic", null, null)));
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[\"sub-a\",\"sub-b\"]}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.profiles['sub-a'].characterImgRef").isEqualTo(avatar)
                .jsonPath("$.profiles['sub-b'].characterImgRef").isEqualTo(sticker);
    }

    @Test
    // The READ side of the same bypass, and the half a charset gate cannot reach: rows
    // written BEFORE the gate existed are still in the table, and "/a/./b" was legal then.
    // The comparison therefore canonicalises the stored value instead of trusting it, so
    // a legacy dot-segment spelling is suppressed exactly like the plain one.
    void lookup_suppressesAnOwnerBlindRefSpelledWithADotSegment() {
        when(profiles.findBySubjects(anyCollection(), any())).thenReturn(Flux.just(
                row("sub-a", "cat", "/bff/user/profile/avatar/./body", "classic", null, null),
                row("sub-b", null, "/bff/user/character/./avatar", "classic", null, null),
                row("sub-c", null, "/bff/user//profile/avatar/body", "classic", null, null)));
        asUser().post().uri("/bff/forum/vn-profiles/lookup").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subjects\":[\"sub-a\",\"sub-b\",\"sub-c\"]}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.profiles['sub-a'].characterImgRef").doesNotExist()
                .jsonPath("$.profiles['sub-a'].stickerSlug").isEqualTo("cat")
                .jsonPath("$.profiles['sub-b'].characterImgRef").doesNotExist()
                .jsonPath("$.profiles['sub-c'].characterImgRef").doesNotExist();
    }

    @Test
    // The canonicaliser the two rules share, pinned directly: what a BROWSER would put on
    // the wire for a stored spelling. Everything above is one consequence of this.
    void wirePath_collapsesEverySpellingABrowserRewrites() {
        String selfServe = VnProfileDto.SELF_AVATAR_BODY_REF;
        assertThat(VnProfileService.wirePath("/bff/user/profile/avatar/./body")).isEqualTo(selfServe);
        assertThat(VnProfileService.wirePath("/bff/user//profile/avatar/body")).isEqualTo(selfServe);
        assertThat(VnProfileService.wirePath("/bff/user/profile/avatar/body/")).isEqualTo(selfServe);
        assertThat(VnProfileService.wirePath("/bff/user/character/../profile/avatar/body"))
                .isEqualTo(selfServe);
        assertThat(VnProfileService.wirePath("/bff/user/profile/avatar/body?x=1")).isEqualTo(selfServe);
        // ...and leaves a canonical path exactly as it is.
        String real = "/bff/user/character/avatar/3f2504e0-4f89-41d3-9a0c-0305e82c3301/body";
        assertThat(VnProfileService.wirePath(real)).isEqualTo(real);
        assertThat(VnProfileService.wirePath("/bff/user/character/portrait.v2.png"))
                .isEqualTo("/bff/user/character/portrait.v2.png");
    }

    @Test
    // The declared rule, pinned as a SET rather than through the two behaviours above:
    // every owner-blind literal is charset-legal (so only this rule stops it) and none of
    // them is a canonical serve shape (so the rule can never swallow a real sprite).
    void ownerBlindRefs_areCharsetLegalButNeverACanonicalServeShape() {
        assertThat(VnProfileDto.OWNER_BLIND_IMG_REFS).isNotEmpty();
        for (String ref : VnProfileDto.OWNER_BLIND_IMG_REFS) {
            assertThat(ref).matches(VnProfileDto.CHARACTER_IMG_REF);
            assertThat(ref).doesNotMatch(VnProfileDto.CANONICAL_AVATAR_REF_SHAPE);
            assertThat(ref).doesNotMatch(VnProfileDto.CANONICAL_STICKER_REF_SHAPE);
            // suppressed for a reader in EVERY spelling that reaches the same endpoint
            assertThat(VnProfileService.renderableImgRef(ref)).isNull();
            assertThat(VnProfileService.renderableImgRef(ref + "/")).isNull();
            assertThat(VnProfileService.renderableImgRef(dotted(ref))).isNull();
        }
        // null passes through untouched (clearing the field is always legal), and a real
        // serve URL is never touched by either gate.
        assertThat(VnProfileService.renderableImgRef(null)).isNull();
        assertThat(VnProfileService.storableImgRef(null)).isNull();
        String real = "/bff/user/character/avatar/3f2504e0-4f89-41d3-9a0c-0305e82c3301/body";
        assertThat(VnProfileService.renderableImgRef(real)).isEqualTo(real);
        assertThat(VnProfileService.storableImgRef(real)).isEqualTo(real);
    }

    @Test
    // The asymmetry between the two gates, stated as its own rule: the READ gate covers
    // both owner-blind spellings, the WRITE gate covers only the one no client ever
    // writes. UNSTORABLE ⊂ OWNER_BLIND, never the other way round — widening the write
    // gate to the whole set is the F2 signal-erasure regression.
    void theWriteGateIsAStrictSubsetOfTheRenderGate() {
        assertThat(VnProfileDto.UNSTORABLE_IMG_REFS)
                .isSubsetOf(VnProfileDto.OWNER_BLIND_IMG_REFS)
                .containsExactly(VnProfileDto.SELF_AVATAR_BODY_REF);
        // the legacy handle ref: never rendered, always stored (it is the repair signal)
        String handle = VnProfileDto.LEGACY_AVATAR_HANDLE_REF;
        assertThat(VnProfileService.renderableImgRef(handle)).isNull();
        assertThat(VnProfileService.storableImgRef(handle)).isEqualTo(handle);
        assertThat(VnProfileService.storableImgRef(dotted(handle))).isEqualTo(dotted(handle));
        // the self-avatar serve: never rendered, never stored, in any spelling
        String self = VnProfileDto.SELF_AVATAR_BODY_REF;
        assertThat(VnProfileService.storableImgRef(self)).isNull();
        assertThat(VnProfileService.storableImgRef(self + "/")).isNull();
        assertThat(VnProfileService.storableImgRef(dotted(self))).isNull();
    }

    /** The same endpoint, spelled with a {@code .} segment a URL parser removes. */
    private static String dotted(String ref) {
        int lastSlash = ref.lastIndexOf('/');
        return ref.substring(0, lastSlash) + "/." + ref.substring(lastSlash);
    }

    @Test
    // The CANONICAL_* constants declare SHAPES, not one string each — and a pin that
    // samples ONE value only catches the narrowings that value happens to exercise.
    // Both original fixtures were lowercase-hex UUIDs, so dropping `_`, `.` or `A-Z`
    // from CHARACTER_IMG_REF's charset left the ENTIRE suite green while rejecting refs
    // these very constants declare legal (only the `/` mutation failed). Cover the
    // declared extremes instead, on the write-path allowlist that actually gates saves.
    void characterImgRefAllowlist_staysASupersetOfEveryCanonicalShape() {
        // Sticker slugs: this repo's STICKER_SLUG must keep mirroring hugmesh-user-bff-api
        // StickerController.SLUG_SHAPE ([a-z0-9_-]{1,64}). `_`, `-`, 1-char and 64-char are
        // all legal there, and hugmesh-forum-ui's own fixtures use them (stickers.spec.ts
        // asserts stickerBodyUrl("b-2_x")). Dropping `_` from CHARACTER_IMG_REF would 400
        // a save for every user whose slug has one.
        for (String slug : List.of("a", "happy_face", "b-2_x", "st-1", "0".repeat(64))) {
            assertThat(slug).as("STICKER_SLUG must keep mirroring user-bff SLUG_SHAPE: %s", slug)
                    .matches(VnProfileDto.STICKER_SLUG);
            String ref = "/bff/user/character/stickers/" + slug + "/body";
            assertThat(ref).as("CANONICAL_STICKER_REF_SHAPE admits %s", ref)
                    .matches(VnProfileDto.CANONICAL_STICKER_REF_SHAPE);
            assertThat(ref).as("CHARACTER_IMG_REF must stay a SUPERSET of it: %s", ref)
                    .matches(VnProfileDto.CHARACTER_IMG_REF);
        }
        // Avatar handles are lowercase hex + `-`; cover both charset extremes.
        for (String handle : List.of("00000000-0000-0000-0000-000000000000",
                                     "ffffffff-ffff-ffff-ffff-ffffffffffff")) {
            String ref = "/bff/user/character/avatar/" + handle + "/body";
            assertThat(ref).as("CANONICAL_AVATAR_REF_SHAPE admits %s", ref)
                    .matches(VnProfileDto.CANONICAL_AVATAR_REF_SHAPE);
            assertThat(ref).as("CHARACTER_IMG_REF must stay a SUPERSET of it: %s", ref)
                    .matches(VnProfileDto.CHARACTER_IMG_REF);
            assertThat(ref.length()).isLessThanOrEqualTo(256);
        }
        // The extension-bearing media shape this repo already stores as a characterImgRef
        // (me_returnsStoredProfile) reaches the allowlist ONLY on the write path, so it is
        // invisible to that read test: pin it here, or dropping `.` also goes unnoticed.
        assertThat("/bff/user/media/img-1.png").matches(VnProfileDto.CHARACTER_IMG_REF);
        // DELIBERATELY NOT PINNED: A-Z. The charset admits it, but no /bff/user/** route
        // in this cross-repo contract produces an uppercase segment (avatar handles are
        // lowercase hex, sticker slugs lowercase — hugmesh-forum-ui's stickers.spec.ts
        // asserts stickerBodyUrl("3F2504E0") is null). Narrowing it is a decision to take
        // openly in its own PR, not one to discover from a broken sprite.
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
