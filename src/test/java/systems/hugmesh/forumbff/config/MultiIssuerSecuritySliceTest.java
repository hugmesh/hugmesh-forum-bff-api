package systems.hugmesh.forumbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.config.TenancyResolvers;
import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The MULTI-ISSUER security slice — replicated VERBATIM (pattern) from the
 * hugmesh-gateway reference (PR #34, branch {@code test/security-slice-keystone};
 * see {@code docs/testing/MULTI-ISSUER-SLICE.md}). Proves this forum-BFF's
 * {@link TenancyResourceServerConfig} per-issuer resolver, wired into the REAL
 * {@link SecurityConfig} filter chain, correctly handles per-brand (multi-issuer)
 * Casdoor tokens with the security property that matters: an UNKNOWN issuer fails
 * CLOSED (401), and a token from one brand can NEVER authenticate as another.
 *
 * <p>Determinism with NO network and NO live Casdoor: each brand's JWKS + OIDC
 * discovery is served by an in-process {@link TestIssuer} on {@code 127.0.0.1}, so
 * {@code ReactiveJwtDecoders.fromIssuerLocation(...)} validates real RSA-signed
 * tokens offline.
 *
 * <p>The three keystones:
 * <ul>
 *   <li>(a) USER-SITUATIONAL — a brand-X-issuer JWT resolves to brand-X's manager →
 *       authenticated, and the {@code DOMAIN_brandx} authority is emitted.</li>
 *   <li>(b) CROSS-USER DENY — a token from an issuer NOT in {@code app.tenancy.issuers}
 *       (well-formed, correctly signed by its own key, just unlisted) → the per-issuer
 *       resolver returns {@code Mono.empty()} → 401 fail-closed, never default-accept.</li>
 *   <li>(c) CROSS-USER DENY — a brand-Y JWT is scoped to brand-Y; it can NEVER become
 *       brand-X (no {@code DOMAIN_brandx}).</li>
 * </ul>
 * Plus the cheap fail-closed neighbours: a tampered signature and a garbage bearer
 * both 401.
 */
class MultiIssuerSecuritySliceTest extends SecuritySliceSupport {

    /**
     * Trivial controller that echoes the authenticated principal's authorities from the
     * {@link ReactiveSecurityContextHolder}. {@code /whoami} sits under {@code /bff/forum/**}
     * so the path-policy floor ({@code .authenticated()}) lets any authenticated token
     * through and we can inspect the emitted authorities (including {@code DOMAIN_<x>}).
     */
    @RestController
    static class AuthoritiesController {
        @GetMapping("/bff/forum/whoami")
        Mono<List<String>> whoami() {
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .sorted()
                            .toList());
        }
    }

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;       // a correctly-signed but UNLISTED issuer
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        // Trusted set = brandX + brandY. rogue is deliberately ABSENT.
        DomainRegistry registry = new DomainRegistry(
                brandX.issuerUri(),
                brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode active (swaps onto the resolver)")
                .isTrue();
        assertThat(registry.isTrusted(rogue.issuerUri()))
                .as("the rogue issuer must NOT be trusted")
                .isFalse();

        // Build the multi-issuer resolver exactly the way the tenancy config contributes
        // it (no back-compat jwk-set-uri => discovery from each iss, which the in-process
        // TestIssuer serves). This is the REAL production resolver bean.
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(
                        new TenancyResourceServerConfig(registry, "", "", false, 600000L));

        client = sliceClient(registry, provider(resolver), new AuthoritiesController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    private List<String> authoritiesFor(String bearer) {
        return client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(bearer))
                .exchange()
                .expectStatus().isOk()
                .expectBody(new org.springframework.core.ParameterizedTypeReference<List<String>>() {})
                .returnResult()
                .getResponseBody();
    }

    // (a) USER-SITUATIONAL — a trusted brand-X token authenticates and gets DOMAIN_brandx.
    @Test
    void brandXToken_authenticatesAndGetsBrandXDomainAuthority() {
        String token = brandX.mint("user-x", List.of("forum"));
        List<String> authorities = authoritiesFor(token);
        assertThat(authorities)
                .as("brand-X token resolves to brand-X's manager and is stamped DOMAIN_brandx")
                .contains("DOMAIN_brandx", "ROLE_USER", "ROLE_FORUM")
                .doesNotContain("DOMAIN_brandy", "DOMAIN_default");
    }

    // (b) CROSS-USER DENY — an UNLISTED issuer fails CLOSED (401). The resolver returns
    // Mono.empty() for an untrusted iss; there is NO default-accept manager.
    @Test
    void unknownIssuerToken_failsClosed_401() {
        String token = rogue.mint("attacker", List.of("forum", "admin"));
        client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // (c) CROSS-USER DENY — a brand-Y token is scoped to brand-Y; it can NEVER become brand-X.
    @Test
    void brandYToken_isScopedToBrandY_neverBrandX() {
        String token = brandY.mint("user-y", List.of("forum", "mod"));
        List<String> authorities = authoritiesFor(token);
        assertThat(authorities)
                .as("brand-Y token is stamped DOMAIN_brandy and NEVER DOMAIN_brandx (cross-brand isolation)")
                .contains("DOMAIN_brandy", "ROLE_USER", "ROLE_FORUM", "ROLE_MOD")
                .doesNotContain("DOMAIN_brandx", "DOMAIN_default");
    }

    // Fail-closed neighbour — a token signed by brand-Y's key but claiming brand-X's iss
    // (tampered: the signature does not match brand-X's published JWKS) → 401.
    @Test
    void tokenWithMismatchedSignature_failsClosed_401() {
        // brandY mints a token but we splice brandX's iss into the claims by minting
        // through brandY with brandX's issuer in a forged claim is not possible via the
        // fixture (iss is stamped by the minting issuer). Instead: tamper a valid
        // brand-X token's payload so its signature no longer verifies against brand-X.
        String valid = brandX.mint("user-x", List.of("forum"));
        String tampered = tamperPayload(valid);
        client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(tampered))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // Fail-closed neighbour — a wrong-KID token: genuinely signed by brand-X's private
    // key and stamped brand-X's iss, but its JWS header kid is NOT in brand-X's published
    // JWK set, so the decoder cannot locate a verification key for it → 401. Distinct from
    // the tampered-payload case (which fails the signature check) and from the unknown-iss
    // case (which is rejected by the allowlist before any key lookup).
    @Test
    void tokenWithWrongKid_failsClosed_401() {
        String wrongKid = brandX.mintWithWrongKid("user-x", List.of("forum"));
        client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth(wrongKid))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // Fail-closed neighbour — a garbage (non-JWT) bearer → 401.
    @Test
    void garbageBearer_failsClosed_401() {
        client.get().uri("/bff/forum/whoami")
                .headers(h -> h.setBearerAuth("not-a-jwt"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** Flip one base64url char in the JWT payload segment so the RS256 signature no
     *  longer verifies (header.PAYLOAD.signature). */
    private static String tamperPayload(String jwt) {
        String[] parts = jwt.split("\\.");
        char[] payload = parts[1].toCharArray();
        // flip the first char to a different valid base64url char
        payload[0] = payload[0] == 'A' ? 'B' : 'A';
        parts[1] = new String(payload);
        return parts[0] + "." + parts[1] + "." + parts[2];
    }
}
