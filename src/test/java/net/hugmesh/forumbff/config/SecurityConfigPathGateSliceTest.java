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
import net.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The COARSE PATH-GATE slice — exercises this repo's real {@code authorizeExchange}
 * policy (in {@link SecurityConfig}) end-to-end through the production filter chain
 * with REAL RS256 tokens (minted by an in-process {@link TestIssuer}, zero network),
 * not mocked authorities. Companion to {@link MultiIssuerSecuritySliceTest}; the slice
 * plumbing is identical (see {@code docs/testing/MULTI-ISSUER-SLICE.md}), only the
 * path/role table changes.
 *
 * <p>What the coarse path policy decides (from {@code SecurityConfig.commonRoutes}):
 * <ul>
 *   <li>{@code /actuator/health} (+ {@code /info}) — {@code permitAll} (no token).</li>
 *   <li>{@code /bff/forum/admin/**} — {@code hasAnyRole("ADMIN","SUPERADMIN")}
 *       (declared BEFORE the floor so the more-specific prefix wins).</li>
 *   <li>{@code /bff/forum/moderation/**} — {@code .authenticated()}, also declared
 *       before the floor purely so the D8 step-up wrapper has a rule to hang off; the
 *       coarse decision is identical to inheriting the floor.</li>
 *   <li>{@code /bff/forum/**} — {@code .authenticated()} (the ROLE_FORUM floor is
 *       enforced upstream at the gateway; here authentication is enough at the path
 *       level — ROLE_* re-checks live at the method level).</li>
 *   <li>{@code anyExchange()} — {@code .authenticated()}.</li>
 * </ul>
 *
 * <p><b>THE no-ADMIN&gt;MOD EDGE IS NOT A PATH GATE.</b> The load-bearing
 * AND-of-MOD+FORUM moderation rule lives at the METHOD level
 * ({@code @PreAuthorize("hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))")}
 * in {@code ModerationController}), NOT in {@code authorizeExchange}: the coarse path
 * policy only floors {@code /bff/forum/moderation/**} to {@code .authenticated()}. So at
 * the FILTER-CHAIN layer a bare authenticated token —
 * even a bare ADMIN — passes the moderation PATH (the 403 happens later, at the
 * method gate, covered by {@code ModerationControllerTest}). This slice asserts the
 * coarse layer's actual decision AND documents the boundary, so a future refactor that
 * tried to move moderation gating into {@code authorizeExchange} (where {@code hasAnyRole}
 * CANNOT express the AND, and where a bare ADMIN would then wrongly pass) is caught.
 *
 * <p>This class always drives the chain with {@code app.mfa.enabled=false} (what
 * {@link SecuritySliceSupport#sliceClient} builds), i.e. TODAY's platform default — the
 * D8 step-up branch is covered separately by {@link MfaStepUpPathGateSliceTest}.
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

    /** Tiny controllers covering the gated path prefixes — they only need to EXIST so
     *  the path policy has something to (dis)allow; the body is never reached on a 401/403. */
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

    @RestController
    static class HealthStub {
        @GetMapping("/actuator/health")
        Mono<String> health() { return Mono.just("UP"); }
    }

    private TestIssuer issuer;
    private DomainRegistry registry;
    private WebTestClient client;       // dev/test chain (spec public)
    private WebTestClient prodClient;   // prod chain (spec ADMIN-gated)

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        // Single-issuer registry (the lone issuer-uri -> DOMAIN_default). NOT multiIssuer,
        // so SecurityConfig stays on the single-issuer o.jwt(...) decoder path. We still
        // need a REAL decoder for that lone issuer; with no tenant resolver (absent()),
        // the slice's o.jwt(...) path relies on the issuer-uri property at runtime — so
        // for the path-gate we drive the MULTI-issuer resolver against a one-brand
        // registry that is trusted, giving us a real working decoder offline without a
        // Spring property context. The path policy under test is identical either way
        // (commonRoutes is shared), and the resolver still 401s an unknown iss.
        registry = new DomainRegistry(issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + issuer.issuerUri() + "/other=brandy");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(
                        new TenancyResourceServerConfig(registry, "", "", false, 600000L));
        Object[] controllers = {new ForumStub(), new AdminStub(), new HealthStub()};
        client = sliceClient(registry, provider(resolver), controllers);
        prodClient = prodSliceClient(registry, provider(resolver), controllers);
    }

    @AfterEach
    void tearDown() {
        issuer.close();
    }

    private String tokenWithRoles(String... roles) {
        return issuer.mint("u", List.of(roles));
    }

    // --- public probe -------------------------------------------------------

    @Test
    void healthProbe_isPublic_noToken() {
        client.get().uri("/actuator/health").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("UP");
    }

    // --- the floor: /bff/forum/** is .authenticated() -----------------------

    @Test
    void forumFloor_unauthenticated_401() {
        client.get().uri("/bff/forum/whoami").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void forumFloor_authenticatedUser_allowed() {
        client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(tokenWithRoles("forum")))
                .exchange()
                .expectStatus().isOk();
    }

    // --- unknown-iss 401 end-to-end (fail-closed) ---------------------------

    @Test
    void unknownIssuer_failsClosed_401_endToEnd() {
        try (TestIssuer rogue = new TestIssuer()) {
            assertThat(registry.isTrusted(rogue.issuerUri())).isFalse();
            client.get().uri("/bff/forum/whoami")
                    .headers(h -> h.setBearerAuth(rogue.mint("attacker", List.of("forum", "admin"))))
                    .exchange()
                    .expectStatus().isUnauthorized();
        }
    }

    // --- the admin path gate: /bff/forum/admin/** is ADMIN/SUPERADMIN --------

    @Test
    void adminPath_plainAuthenticatedUser_forbidden_403() {
        // A real, trusted, authenticated token WITHOUT ADMIN/SUPERADMIN: the floor would
        // accept it, but the more-specific /bff/forum/admin/** rule requires the role -> 403.
        client.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(tokenWithRoles("forum", "user")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void adminPath_mod_isNotAdmin_forbidden_403() {
        // The load-bearing sibling-roles property at the PATH layer: a bare MOD is NOT an
        // admin (no ADMIN>MOD hierarchy edge), so it cannot reach the admin path.
        client.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(tokenWithRoles("mod")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void adminPath_admin_allowed() {
        client.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(tokenWithRoles("admin")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void adminPath_superadmin_allowed_viaRoleHierarchy() {
        client.get().uri("/bff/forum/admin/stats")
                .headers(h -> h.setBearerAuth(tokenWithRoles("superadmin")))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void adminPath_unauthenticated_401() {
        client.get().uri("/bff/forum/admin/stats").exchange()
                .expectStatus().isUnauthorized();
    }

    // --- moderation PATH layer: a bare authenticated token passes the PATH ---
    // (the AND-of-MOD+FORUM 403 is a METHOD gate — see class javadoc + ModerationControllerTest).

    @Test
    void moderationPath_coarseLayer_floorsToAuthenticated_notAndGate() {
        // Documents the method-vs-path boundary: at the filter-chain layer the moderation
        // path is just .authenticated() — a bare authenticated token (no MOD, no FORUM)
        // is NOT 401/403 by the PATH policy (the route reaches the controller; the method
        // gate is what enforces the AND). Asserting NOT-401 here pins the coarse layer's
        // decision so a refactor that accidentally hardened/loosened the PATH is caught.
        client.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(tokenWithRoles("user")))
                .exchange()
                .expectStatus().value(s -> assertThat(s).isNotEqualTo(HttpStatus.UNAUTHORIZED.value()));
    }

    @Test
    void moderationPath_unauthenticated_401() {
        client.get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isUnauthorized();
    }

    // --- prod chain: OpenAPI spec paths require ADMIN/SUPERADMIN -------------

    @Test
    void prodChain_specPath_plainUser_forbidden_403() {
        prodClient.get().uri("/v3/api-docs")
                .headers(h -> h.setBearerAuth(tokenWithRoles("forum", "user")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void prodChain_specPath_unauthenticated_401() {
        prodClient.get().uri("/v3/api-docs").exchange()
                .expectStatus().isUnauthorized();
    }
}
