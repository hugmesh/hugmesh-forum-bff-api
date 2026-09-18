package net.hugmesh.forumbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
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
import net.hugmesh.forumbff.security.ForumStepUpGate;
import net.hugmesh.forumbff.security.Roles;
import net.hugmesh.forumbff.testsupport.TestIssuer;
import net.hugmesh.forumbff.web.StepUpRequiredException;

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

        /**
         * Stands in for {@code ModerationController}'s method-level
         * {@code @PreAuthorize("hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))")}.
         * A slice built with {@code WebTestClient.bindToController} has no method security, so
         * the denial is raised directly — what matters here is only that an
         * {@link AccessDeniedException} raised AFTER the path gate granted reaches the chain's
         * access-denied handler, which is exactly what reactive method security does.
         */
        @GetMapping("/moderation/method-gated")
        Mono<String> methodGated() {
            return Mono.error(new AccessDeniedException("not a moderator of this forum"));
        }
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
    private WebTestClient mfaOnProd; // ditto, but the PROD chain — see mfaProdSliceClient

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
        // The chain every deployment actually runs. Only the OpenAPI-spec gating differs from
        // the dev/test chain, so the step-up assertions must hold identically on both — and
        // the dev chain alone cannot prove that (see #15 / mod-bff PR #18's M7 mutation).
        mfaOnProd = mfaProdSliceClient(registry, provider(resolver(registry, true)), controllers);
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

    // --- #15: the step-up 403 must be DISTINGUISHABLE from a role 403 --------
    //
    // Everything above asserts WHAT is denied. This section asserts what the denial SAYS —
    // the half hugmesh-forum-ui needs and could not previously see. Nothing here changes a
    // single authorization outcome; every status asserted below is the status the test above
    // it already asserted.

    /** {@code X-Step-Up-Required: X-Forum-StepUp} — the platform signal, byte for byte. */
    private static final String SIGNAL = StepUpRequiredException.SIGNAL_HEADER;

    /**
     * What {@code BearerTokenServerAccessDeniedHandler} — Spring's own default on a chain
     * that configures {@code oauth2ResourceServer}, and therefore this service's pass-through
     * delegate — sends on an AUTHENTICATED 403. Spelled out in full because it IS the
     * regression surface: every character of it disappears if the delegate is ever swapped
     * for the bare status handler, and no other test in this repo would notice.
     */
    private static final String INSUFFICIENT_SCOPE =
            "Bearer error=\"insufficient_scope\", "
                    + "error_description=\"The request requires higher privileges than provided "
                    + "by the access token.\", "
                    + "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"";

    @Test
    void mfaEnabled_adminPath_withoutStamp_carriesTheStepUpSignal() {
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(plainToken("admin")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.error").isEqualTo(
                        "forum administration requires step-up re-authentication "
                                + "(present X-Forum-StepUp)")
                // The shared {"error": ...} shape, unchanged: nothing was added to the body,
                // so no unrelated error's wire shape moves.
                .jsonPath("$.length()").isEqualTo(1);
    }

    @Test
    void mfaEnabled_adminPath_staleStamp_carriesTheStepUpSignal() {
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(
                        steppedUpToken(FRESHNESS_WINDOW_MILLIS + 60_000L, "admin")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER)
                .expectBody(String.class)
                .value(b -> assertThat(b).contains(StepUpRequiredException.LEGACY_PHRASE));
    }

    @Test
    void mfaEnabled_moderationPath_withoutStamp_carriesTheStepUpSignal() {
        mfaOn.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(plainToken("mod", "forum")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER)
                .expectBody()
                .jsonPath("$.error").isEqualTo(
                        "forum moderation requires step-up re-authentication "
                                + "(present X-Forum-StepUp)");
    }

    @Test
    void mfaEnabled_moderationPath_staleStamp_carriesTheStepUpSignal() {
        mfaOn.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(
                        steppedUpToken(FRESHNESS_WINDOW_MILLIS + 60_000L, "mod", "forum")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER)
                .expectBody(String.class)
                .value(b -> assertThat(b).contains(StepUpRequiredException.LEGACY_PHRASE));
    }

    /**
     * THE assertion that stops a routine refusal from popping an MFA dialog. A fully
     * stepped-up NON-admin is refused on the very same path by the ROLE half, and that
     * refusal must stay unsignalled — a challenge cannot possibly let them through, so
     * offering one is a dead end the user cannot escape.
     *
     * <p>It also pins the pass-through end to end: the refusal still carries the full RFC 6750
     * {@code insufficient_scope} challenge and an empty body, i.e. exactly what this chain
     * sent before this change. That whole challenge string is what a delegate of
     * {@code HttpStatusServerAccessDeniedHandler} would have destroyed — and it is only
     * visible on an AUTHENTICATED request, which is why it is asserted here and not only in
     * {@link StepUpAccessDeniedWiringTest}.
     */
    @Test
    void mfaEnabled_roleDenialOnTheSamePath_carriesNoSignal_andIsUnchanged() {
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "forum", "user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(SIGNAL)
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, INSUFFICIENT_SCOPE)
                .expectBody().isEmpty();
    }

    /** A role denial on the moderation path — no ROLE_* at all, so the base
     *  {@code .authenticated()} leg is what refuses — likewise carries no signal. */
    @Test
    void mfaEnabled_unauthenticated_carriesNoSignal() {
        // Never reaches the access-denied handler at all: ExceptionTranslationWebFilter routes
        // an absent principal to the authentication entry point (401), so there is nothing to
        // dress up as a step-up requirement.
        mfaOn.get().uri("/bff/forum/admin/stats").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist(SIGNAL);
        mfaOn.get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist(SIGNAL);
    }

    /**
     * A forged {@code permissions:["MFA_SATISFIED"]} is dropped by the converter's
     * reserved-prefix guard, so the caller is an admin who has genuinely not stepped up — and
     * the signal is CORRECT for them: completing a real challenge is exactly what would let
     * them through. Pinned so the forged-marker case is not mistaken for a leak: the signal
     * grants nothing, it only names the flavour of a refusal that already happened.
     */
    @Test
    void mfaEnabled_forgedPermissionMarker_getsARealStepUpSignal_notAGrant() {
        String forged = token(List.of("admin"),
                Map.of("permissions", List.of(Roles.MFA_SATISFIED)));
        mfaOn.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(forged))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER);
    }

    // --- flag OFF: the signal must NEVER appear ------------------------------

    /**
     * While MFA is dark {@code stepUp} hands {@code base} straight back, so nothing can record
     * a step-up denial and the handler is a pure pass-through. This is the whole org today:
     * {@code app.mfa.enabled=false} everywhere, so this is the branch production is on.
     */
    @Test
    void mfaDisabled_aRoleDenial_carriesNoSignal_andIsUnchanged() {
        mfaOff.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(plainToken("forum", "user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(SIGNAL)
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, INSUFFICIENT_SCOPE)
                .expectBody().isEmpty();
    }

    @Test
    void mfaDisabled_anAdminWithNoStamp_isStillAllowed_andNothingSignals() {
        // Belt and braces on the regression this repo cannot afford: not only is the admin
        // still allowed through (asserted above), the new wiring adds no header to the 200.
        mfaOff.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(plainToken("admin")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist(SIGNAL);
    }

    // --- the PROD chain, which no other slice in this repo exercises ---------

    /**
     * Every other client here builds {@code devFilterChain}; compose and the cluster both run
     * profile-less and therefore take {@code filterChain}. Deleting
     * {@code .exceptionHandling(...)} from the prod chain alone would leave every assertion
     * above green while production lost the signal entirely — that mutation is caught here
     * and, structurally, by {@link StepUpAccessDeniedWiringTest}.
     */
    @Test
    void mfaEnabled_prodChain_adminPath_withoutStamp_carriesTheStepUpSignal() {
        mfaOnProd.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(plainToken("admin")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER);
    }

    @Test
    void mfaEnabled_prodChain_moderationPath_withoutStamp_carriesTheStepUpSignal() {
        mfaOnProd.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(plainToken("mod", "forum")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(SIGNAL, ForumStepUpGate.STEP_UP_HEADER);
    }

    /**
     * The case issue #15 calls out by name, and the one that kills the "record it
     * unconditionally" shortcut: a caller who HAS stepped up passes the path gate and is then
     * refused by the method-level MOD∧FORUM gate. That 403 must carry NO signal — offering an
     * MFA challenge to someone who has already completed one is a loop with no exit.
     *
     * <p>It is also the only assertion in this repo that fails if {@code stepUp} records the
     * surface on the GRANTED branch as well as the denied one: every other path either never
     * reaches the handler (a 200) or never granted in the first place.
     */
    @Test
    void mfaEnabled_aMethodLevelDenialAfterTheGateGranted_carriesNoSignal() {
        mfaOn.get().uri("/bff/forum/moderation/method-gated")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "mod", "forum")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(SIGNAL)
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, INSUFFICIENT_SCOPE)
                .expectBody().isEmpty();
    }

    /** Same shape with MFA dark — the wrapper is not even installed, so nothing can record. */
    @Test
    void mfaDisabled_aMethodLevelDenial_carriesNoSignal() {
        mfaOff.get().uri("/bff/forum/moderation/method-gated")
                .headers(h -> h.setBearerAuth(plainToken("mod", "forum")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(SIGNAL);
    }

    @Test
    void mfaEnabled_prodChain_roleDenial_carriesNoSignal() {
        mfaOnProd.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(steppedUpToken(1_000L, "forum", "user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(SIGNAL);
    }
}
