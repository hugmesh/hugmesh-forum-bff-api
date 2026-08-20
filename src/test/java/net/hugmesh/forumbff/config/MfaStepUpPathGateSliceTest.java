package net.hugmesh.forumbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.forumbff.security.Roles;
import net.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The D8 STEP-UP path gate — {@code SecurityConfig.stepUp} wrapping
 * {@code /bff/forum/admin/**} and {@code /bff/forum/moderation/**}. Same slice plumbing
 * as {@link SecurityConfigPathGateSliceTest} (real RS256 tokens from an in-process
 * {@link TestIssuer}, the production filter chain, zero network); the ONE difference is
 * that this class also drives the chain with {@code app.mfa.enabled=true} so BOTH
 * branches of the flag are asserted against the SAME policy code.
 *
 * <p><b>The two load-bearing properties.</b>
 * <ol>
 *   <li><b>Dark = no-op.</b> With the flag OFF the marker is NEVER derived, so an
 *       unconditional step-up check would 403 every admin on the platform TODAY. The
 *       disabled-branch tests pin that today's callers are untouched.</li>
 *   <li><b>Flip = enforced.</b> With the flag ON the privileged paths demand the
 *       {@link Roles#MFA_SATISFIED} marker, which the converter derives ONLY from a
 *       FRESH {@code mfa_satisfied_at} claim — so enforcement arrives WITH the platform
 *       flag rather than needing a follow-up change here.</li>
 * </ol>
 *
 * <p>The marker is a RESERVED converter prefix, so the forged-{@code permissions} case is
 * asserted too: a caller cannot mint their own second factor.
 */
class MfaStepUpPathGateSliceTest extends SecuritySliceSupport {

    /** 10 minutes — the {@code app.mfa.freshness-window} default both slices are built with. */
    private static final long FRESHNESS_WINDOW_MILLIS = 600_000L;

    /** Same stub shape as the coarse path-gate slice: the bodies are never reached on 401/403. */
    @RestController
    @RequestMapping("/bff/forum")
    static class ForumStub {
        @GetMapping("/whoami")
        Mono<String> whoami() { return Mono.just("ok"); }
        @GetMapping("/moderation/queue")
        Mono<String> moderation() { return Mono.just("ok"); }
    }

    @RestController
    @RequestMapping("/bff/forum/admin")
    static class AdminStub {
        @GetMapping("/stats")
        Mono<String> stats() { return Mono.just("ok"); }
    }

    private TestIssuer issuer;
    private WebTestClient mfaOff;   // app.mfa.enabled=false — today's platform default
    private WebTestClient mfaOn;    // app.mfa.enabled=true  — the post-flip platform

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        // Two entries so DomainRegistry.isMultiIssuer() is true and SecurityConfig takes
        // the resolver path (the single-issuer o.jwt(...) path would need a Spring
        // property context to build a decoder). Identical to the coarse path-gate slice.
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + issuer.issuerUri() + "/other=brandy");
        Object[] controllers = {new ForumStub(), new AdminStub()};
        // Same reason as SecurityConfigPathGateSliceTest: drive the multi-issuer resolver
        // against a one-brand trusted registry so the slice has a REAL offline decoder
        // without a Spring property context. The MFA flag must be set on the resolver too
        // — that is what derives the marker — and on SecurityConfig, which enforces it.
        mfaOff = sliceClient(registry, provider(resolver(registry, false)), controllers);
        mfaOn = mfaSliceClient(registry, provider(resolver(registry, true)), controllers);
    }

    @AfterEach
    void tearDown() {
        issuer.close();
    }

    private static ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver(
            DomainRegistry registry, boolean mfaEnabled) {
        return TenancyResolvers.tenantResolver(new TenancyResourceServerConfig(
                registry, "", "", mfaEnabled, FRESHNESS_WINDOW_MILLIS));
    }

    /** A token carrying the Casdoor {@code roles} claim and, optionally, extra claims. */
    private String token(List<String> roles, Map<String, Object> extraClaims) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("roles", roles.stream().map(r -> Map.of("name", r)).toList());
        claims.put("name", "u");
        claims.putAll(extraClaims);
        return issuer.mintWithClaims("u", claims);
    }

    private String plainToken(String... roles) {
        return token(List.of(roles), Map.of());
    }

    /** A token whose {@code mfa_satisfied_at} stamp is {@code ageMillis} old (string, as Casdoor emits it). */
    private String steppedUpToken(long ageMillis, String... roles) {
        return token(List.of(roles), Map.of(Roles.MFA_SATISFIED_AT_CLAIM,
                String.valueOf(System.currentTimeMillis() - ageMillis)));
    }

    // --- flag OFF: the wrapper is a NO-OP (today's behaviour, unchanged) ------

    @Test
    void mfaDisabled_admin_withoutAnyStamp_stillAllowed() {
        // THE regression this repo cannot afford: with MFA dark the converter never emits
        // the marker, so a gate that checked it unconditionally would lock out every admin.
        mfaOff.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(plainToken("admin")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mfaDisabled_moderationPath_bareUser_stillPassesTheCoarseLayer() {
        // The newly-declared moderation matcher must floor to exactly what inheriting
        // /bff/forum/** already did: .authenticated(). The AND-of-MOD+FORUM stays a
        // METHOD gate (ModerationControllerTest), so the PATH must not 401/403 here.
        mfaOff.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(plainToken("user")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mfaDisabled_forumFloor_unchanged() {
        mfaOff.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(plainToken("forum")))
                .exchange()
                .expectStatus().isOk();
    }

    // --- flag ON: the admin path demands a FRESH second factor ---------------

    @Test
    void mfaEnabled_adminPath_withoutStamp_forbidden_403() {
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(plainToken("admin")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_adminPath_freshStamp_allowed() {
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "admin")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mfaEnabled_adminPath_staleStamp_forbidden_403() {
        // Just outside the 10-minute window -> Roles.isMfaSatisfied is false -> no marker.
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(steppedUpToken(FRESHNESS_WINDOW_MILLIS + 60_000L, "admin")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_adminPath_superadmin_freshStamp_allowed() {
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "superadmin")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mfaEnabled_adminPath_stepUpDoesNotReplaceTheRole() {
        // Step-up NARROWS, it never widens: a fully stepped-up NON-admin is still 403.
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "forum", "user")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_adminPath_forgedPermissionMarker_forbidden_403() {
        // MFA_SATISFIED is a RESERVED converter prefix — a self-asserted permissions entry
        // is dropped before it reaches the gate, so a caller cannot mint their own factor.
        String forged = token(List.of("admin"),
                Map.of("permissions", List.of(Roles.MFA_SATISFIED)));
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(forged))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_adminPath_unauthenticated_stillUnauthorized_401() {
        // The base rule short-circuits, so an absent token is still 401 (not a step-up 403).
        mfaOn.get().uri("/bff/forum/admin/stats").exchange()
                .expectStatus().isUnauthorized();
    }

    // --- flag ON: the moderation path demands a FRESH second factor ----------

    @Test
    void mfaEnabled_moderationPath_withoutStamp_forbidden_403() {
        mfaOn.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(plainToken("mod", "forum")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moderationPath_freshStamp_passesTheCoarseLayer() {
        mfaOn.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "mod", "forum")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mfaEnabled_moderationPath_staleStamp_forbidden_403() {
        mfaOn.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(
                        steppedUpToken(FRESHNESS_WINDOW_MILLIS + 60_000L, "mod", "forum")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moderationPath_unauthenticated_stillUnauthorized_401() {
        mfaOn.get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isUnauthorized();
    }

    // --- flag ON: the ordinary forum floor is NOT step-up gated --------------

    @Test
    void mfaEnabled_forumFloor_isNotStepUpGated() {
        // Reading/posting in the forum is not a privileged action — only the admin and
        // moderation groups are step-up surfaces, so a plain user with NO stamp still passes.
        mfaOn.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(plainToken("forum")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mfaEnabled_forumFloor_unauthenticated_401() {
        mfaOn.get().uri("/bff/forum/whoami").exchange()
                .expectStatus().value(s -> assertThat(s).isEqualTo(HttpStatus.UNAUTHORIZED.value()));
    }
}
