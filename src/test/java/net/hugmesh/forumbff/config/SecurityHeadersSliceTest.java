package net.hugmesh.forumbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

/**
 * WebFlux SECURITY-SLICE test for the hardened reactive HTTP-security HEADERS added to
 * {@link SecurityConfig} (the OWASP secure-headers / NIST 800-228 API-defensive
 * minimum). Drives a real controller THROUGH the production filter chain with a REAL
 * RS256 token (in-process {@link TestIssuer}, zero network) using the same
 * {@link SecuritySliceSupport} scaffolding as the path-gate slice.
 *
 * <p>This BFF is a pure-JSON resource server that always sits BEHIND the
 * hugmesh-gateway, so it re-asserts only the API-defensive minimum (per the audit
 * plan): a deny-everything CSP, an explicit {@code Referrer-Policy: no-referrer}, and
 * Spring's secure defaults (X-Content-Type-Options nosniff, X-Frame-Options DENY).
 * HSTS / Permissions-Policy / COOP / CORP are DELIBERATELY ABSENT (they belong only at
 * the TLS front door / document host), so this test ASSERTS they are not emitted — a
 * regression that wrongly added HSTS over the plaintext intra-mesh hop is caught.
 *
 * <p>The headers are ADDITIVE: this test also re-confirms an unauthenticated request to
 * a protected route still 401s (behaviour-preserving for authz), and that the same
 * hardened headers ride a 401 response too (headers are emitted before the auth
 * decision).
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

    @RestController
    @RequestMapping("/bff/forum")
    static class ForumStub {
        @GetMapping("/whoami")
        Mono<String> whoami() { return Mono.just("ok"); }
    }

    private TestIssuer issuer;
    private DomainRegistry registry;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        // One-brand trusted registry driving the real multi-issuer resolver so we get a
        // working offline decoder (same approach as SecurityConfigPathGateSliceTest); the
        // header policy under test is shared by both chains and independent of this.
        registry = new DomainRegistry(issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + issuer.issuerUri() + "/other=brandy");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(
                        new TenancyResourceServerConfig(registry, "", "", false, 600000L));
        client = sliceClient(registry, provider(resolver), new ForumStub());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
    }

    private String token(String... roles) {
        return issuer.mint("u", List.of(roles));
    }

    // --- hardened headers present on an authenticated 200 -------------------

    @Test
    void authenticatedResponse_carriesHardenedHeaders() {
        client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(token("forum")))
                .exchange()
                .expectStatus().isOk()
                // ADDED by this change:
                .expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                // Spring secure DEFAULTS — must remain present (not disabled):
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                // DELIBERATELY ABSENT on a JSON BFF (front-door-only headers):
                .expectHeader().doesNotExist("Strict-Transport-Security")
                .expectHeader().doesNotExist("Permissions-Policy")
                .expectHeader().doesNotExist("Cross-Origin-Opener-Policy");
    }

    // --- the headers also ride a fail-closed 401 (emitted before authz) -----

    @Test
    void unauthenticatedRequest_still401_andCarriesHardenedHeaders() {
        client.get().uri("/bff/forum/whoami")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().doesNotExist("Strict-Transport-Security");
    }
}
