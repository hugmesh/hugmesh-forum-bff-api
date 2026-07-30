package systems.hugmesh.forumbff.config;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FULL-CONTEXT multi-issuer 401 fail-closed coverage — the previously-untested gap the
 * D6 (cookie/opaque-session) + D8 (MFA challenge stamping) changes will ride on.
 *
 * <p><b>Why this is distinct from the existing slices.</b>
 * {@link MultiIssuerSecuritySliceTest} and {@link SecurityConfigPathGateSliceTest} build
 * {@link SecurityConfig} and {@link TenancyResourceServerConfig} BY HAND (a slice
 * {@code WebTestClient} over a hand-constructed filter chain). They prove the resolver's
 * logic, but they do NOT exercise the production WIRING that decides whether the
 * multi-issuer resolver is used at all:
 * <ul>
 *   <li>the {@code @ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")}
 *       activation of the {@link TenancyResourceServerConfig} bean;</li>
 *   <li>{@link SecurityConfig#resourceServer} choosing the resolver path ONLY when
 *       {@code resolver != null && domainRegistry.isMultiIssuer()} — vs the single-issuer
 *       {@code o.jwt(...)} path;</li>
 *   <li>the {@link DomainRegistry} bean built from the REAL {@code app.tenancy.issuers}
 *       property at context start.</li>
 * </ul>
 * This test boots the WHOLE application (the {@code test} profile + the real auto-config)
 * with {@code app.tenancy.issuers} populated from two in-process {@link TestIssuer}s, so
 * the conditional fires, the registry is multi-issuer, and the resolver is wired by the
 * production code — then it drives real RS256 tokens through that booted security chain.
 *
 * <p><b>Offline + deterministic.</b> Each brand's OIDC discovery doc + JWKS is served by
 * an in-process JDK {@code HttpServer} on {@code 127.0.0.1} (see {@link TestIssuer}), so
 * {@code ReactiveJwtDecoders.fromIssuerLocation(...)} — and the Spring-Boot-auto-configured
 * back-compat decoder built from {@code issuer-uri} (pointed at brand X) — resolve with NO
 * network egress and NO live Casdoor. The DB is a real Testcontainers Postgres wired by
 * {@link PostgresTestSupport} (r2dbc + Liquibase on a fresh per-class database) so the
 * full context boots over the real schema.
 *
 * <p><b>The fail-closed assertions (the load-bearing security property).</b>
 * <ul>
 *   <li>(a) a token from a VALID configured issuer (brand X) is ACCEPTED (200) and
 *       stamped its own {@code DOMAIN_brandx} — never another brand's;</li>
 *   <li>(b) a token from a FOREIGN / unconfigured issuer is REJECTED with 401 — the
 *       per-issuer resolver returns {@code Mono.empty()} for an unlisted {@code iss}, so
 *       there is NO default-accept manager and the request is never treated as
 *       anonymous-allowed;</li>
 *   <li>(c) a tampered-signature token AND a wrong-{@code kid} token (genuinely signed by
 *       brand X's key but under a {@code kid} absent from brand X's published JWKS) both
 *       401 — the platform refuses any token it cannot cryptographically verify.</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@Import(MultiIssuer401FailClosedSpringBootTest.WhoAmITestConfig.class)
class MultiIssuer401FailClosedSpringBootTest extends PostgresTestSupport {

    /**
     * Two trusted brands + one foreign (unlisted) issuer. STATIC so they exist before
     * {@link #tenancyIssuers(DynamicPropertyRegistry)} runs (it executes during context
     * preparation, before any instance field is set) and so all test methods share the
     * SAME issuer URIs the booted context was wired with.
     */
    private static final TestIssuer BRAND_X = new TestIssuer();
    private static final TestIssuer BRAND_Y = new TestIssuer();
    private static final TestIssuer FOREIGN = new TestIssuer();   // correctly-signed, but NOT configured

    /**
     * Wire the REAL multi-issuer properties into the booted context:
     * <ul>
     *   <li>{@code app.tenancy.issuers} = brandX=brandx,brandY=brandy — contains '=', so
     *       {@link TenancyResourceServerConfig}'s {@code @ConditionalOnExpression} fires
     *       and {@link DomainRegistry#isMultiIssuer()} is true (two entries);</li>
     *   <li>{@code spring.security.oauth2.resourceserver.jwt.issuer-uri} = brand X — the
     *       back-compat single issuer. Spring Boot auto-configures a {@code ReactiveJwtDecoder}
     *       from it at startup (discovery against brand X's in-process server, offline), so
     *       the context boots even though the resolver path is the one actually used.</li>
     * </ul>
     * The {@code FOREIGN} issuer is deliberately absent from both properties.
     */
    @DynamicPropertySource
    static void tenancyIssuers(DynamicPropertyRegistry registry) {
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
    }

    @AfterAll
    static void stopIssuers() {
        BRAND_X.close();
        BRAND_Y.close();
        FOREIGN.close();
    }

    @Autowired WebTestClient webTestClient;

    // Sanity: the production wiring really did take the multi-issuer path in the booted
    // context — the resolver bean is present and the registry is multi-issuer. If this
    // ever regresses to the single-issuer o.jwt(...) path, the fail-closed semantics
    // below would no longer be the resolver's, so pin it.
    @Autowired DomainRegistry domainRegistry;
    @Autowired(required = false)
    ReactiveAuthenticationManagerResolver<ServerWebExchange> tenantAuthManagerResolver;

    @Test
    void productionWiring_tookTheMultiIssuerPath() {
        assertThat(domainRegistry.isMultiIssuer())
                .as("two configured issuers => the registry is multi-issuer in the booted context")
                .isTrue();
        assertThat(tenantAuthManagerResolver)
                .as("the @ConditionalOnExpression tenancy resolver bean is present (issuers contains '=')")
                .isNotNull();
        assertThat(domainRegistry.isTrusted(FOREIGN.issuerUri()))
                .as("the foreign issuer is NOT in the configured allowlist")
                .isFalse();
    }

    // (a) VALID configured issuer => ACCEPTED (200), stamped its OWN domain only.
    @Test
    void validConfiguredIssuerToken_isAccepted_andStampedItsOwnDomain() {
        String token = BRAND_X.mint("user-x", List.of("forum"));
        List<String> authorities = whoami(token);
        assertThat(authorities)
                .as("brand-X token validated by brand-X's manager; stamped DOMAIN_brandx, not another brand")
                .contains("DOMAIN_brandx", "ROLE_USER", "ROLE_FORUM")
                .doesNotContain("DOMAIN_brandy", "DOMAIN_default");
    }

    // (a') the OTHER configured issuer is likewise accepted and isolated to its own domain
    // — proving acceptance is per-issuer, not a blanket "any signed token" accept.
    @Test
    void otherConfiguredIssuerToken_isAccepted_andIsolatedToItsOwnDomain() {
        String token = BRAND_Y.mint("user-y", List.of("forum", "mod"));
        List<String> authorities = whoami(token);
        assertThat(authorities)
                .as("brand-Y token is stamped DOMAIN_brandy and NEVER DOMAIN_brandx (cross-brand isolation)")
                .contains("DOMAIN_brandy", "ROLE_USER", "ROLE_FORUM", "ROLE_MOD")
                .doesNotContain("DOMAIN_brandx", "DOMAIN_default");
    }

    // (b) FOREIGN / unconfigured issuer => 401 fail-closed. The token is well-formed and
    // correctly signed by its OWN key; it is rejected purely because its iss is not in the
    // allowlist. It is NOT silently accepted and NOT treated as anonymous-allowed.
    @Test
    void foreignUnconfiguredIssuerToken_isRejected_401_failClosed() {
        String token = FOREIGN.mint("attacker", List.of("forum", "admin", "superadmin"));
        webTestClient.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // (b') the foreign-issuer 401 is a HARD reject, never a silent fall-through to an
    // unauthenticated-but-allowed response. Re-assert against a path that would 401 only
    // if authentication is genuinely absent (the floor is .authenticated()).
    @Test
    void foreignUnconfiguredIssuerToken_isNeverTreatedAsAnonymousAllowed() {
        String token = FOREIGN.mint("attacker", List.of("forum"));
        // 401 means the bearer was REJECTED (not accepted, not ignored-and-allowed). A
        // fail-OPEN bug would instead surface 200 (silently accepted) or a 2xx body.
        webTestClient.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    // (c) tampered-signature token => 401. A valid brand-X token whose payload byte was
    // flipped so the RS256 signature no longer verifies against brand-X's JWKS.
    @Test
    void tamperedSignatureToken_isRejected_401() {
        String tampered = tamperPayload(BRAND_X.mint("user-x", List.of("forum")));
        webTestClient.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(tampered))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // (c') wrong-kid token => 401. Genuinely signed by brand-X's private key and stamped
    // brand-X's iss, but its JWS header kid is NOT in brand-X's published JWK set, so the
    // decoder cannot locate a verification key. The platform refuses a token it cannot
    // cryptographically verify rather than guessing a key or default-accepting.
    @Test
    void wrongKidToken_isRejected_401() {
        String wrongKid = BRAND_X.mintWithWrongKid("user-x", List.of("forum"));
        webTestClient.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(wrongKid))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // Fail-closed neighbour — a garbage (non-JWT) bearer => 401.
    @Test
    void garbageBearer_isRejected_401() {
        webTestClient.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth("not-a-jwt"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // No bearer at all => 401 (the /bff/forum/** floor is .authenticated()). Confirms the
    // path is genuinely guarded, so the 200s above are real authentications, not a public
    // endpoint.
    @Test
    void noBearer_isRejected_401() {
        webTestClient.get().uri("/bff/forum/whoami")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private List<String> whoami(String bearer) {
        return webTestClient.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(bearer))
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<List<String>>() {})
                .returnResult()
                .getResponseBody();
    }

    /** Flip one base64url char in the JWT payload segment so the RS256 signature no
     *  longer verifies (header.PAYLOAD.signature). */
    private static String tamperPayload(String jwt) {
        String[] parts = jwt.split("\\.");
        char[] payload = parts[1].toCharArray();
        payload[0] = payload[0] == 'A' ? 'B' : 'A';
        parts[1] = new String(payload);
        return parts[0] + "." + parts[1] + "." + parts[2];
    }

    /**
     * A trivial authenticated endpoint under {@code /bff/forum/**} that echoes the
     * authenticated principal's authorities. It carries NO method {@code @PreAuthorize},
     * so the only gate it hits is the resource server + the {@code .authenticated()} path
     * floor — isolating the JWT-VALIDATION decision (the thing under test) from forum
     * business logic. Mirrors the slice tests' {@code AuthoritiesController}.
     */
    @TestConfiguration
    static class WhoAmITestConfig {
        @Bean
        WhoAmIController whoAmIController() {
            return new WhoAmIController();
        }
    }

    @RestController
    static class WhoAmIController {
        @GetMapping("/bff/forum/whoami")
        Mono<List<String>> whoami() {
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .sorted()
                            .toList());
        }
    }
}
