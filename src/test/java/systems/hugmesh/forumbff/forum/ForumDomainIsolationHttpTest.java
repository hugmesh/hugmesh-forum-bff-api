package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;

/**
 * DATA-PLANE DOMAIN ISOLATION THROUGH THE CONTROLLER (mission item 1) — the gap the
 * controller-slice tests ({@link ForumAdminControllerTest}) and the repo slice
 * ({@link ForumDomainScopeTest}) each only cover HALF of. The slice tests MOCK
 * {@link ForumService} (so the issuer→domain derivation is never exercised end-to-end),
 * and the repo slice passes an explicit {@code domain} string (so the
 * server-derives-domain-from-the-validated-JWT-issuer property is never proven). This
 * test drives the REAL controller → REAL {@link ForumService} → REAL repositories over
 * a REAL (H2-PG-compat) Liquibase schema, authenticated by REAL RS256 tokens minted by
 * per-brand in-process {@link TestIssuer}s, with the per-issuer multi-issuer resolver
 * wired into the production {@code SecurityConfig} filter chain — NO mocked authorities,
 * NO mocked decoder, NO mocked service.
 *
 * <p>The load-bearing invariant: the {@code domain} a forum admin reads/writes is taken
 * from the cryptographically-validated token ISSUER, NEVER from a request param/body.
 * So:
 * <ul>
 *   <li><b>CROSS-USER DENY (read)</b> — a brand-X admin's {@code GET /bff/forum/admin/audit}
 *       returns ONLY brand-X rows; brand-Y's audit trail is invisible.</li>
 *   <li><b>CROSS-USER DENY (param-forge)</b> — appending {@code ?domain=brandy} does NOT
 *       widen the read; the issuer wins, so the brand-X admin still sees only brand-X.</li>
 *   <li><b>WRITE isolation</b> — a brand-X admin's ban audits a brand-X-stamped row that
 *       a brand-Y admin can never read (and vice versa).</li>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — a SUPERADMIN (cross-domain bypass, issuer-agnostic)
 *       reads BOTH brands' trails.</li>
 * </ul>
 *
 * <p>The phpBB extension + ban congruence stay STUBBED ({@code phpbb.enabled=false},
 * {@code external.forum.enabled=false}) per the {@code test} profile — a stubbed ban is
 * still fully audited, which is exactly what lets us assert the audit-trail isolation
 * without a live phpBB.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ForumDomainIsolationHttpTest extends PostgresTestSupport {

    // Per-brand issuers must exist BEFORE the Spring context boots so
    // @DynamicPropertySource can publish their (dynamic-port) issuer URIs into
    // app.tenancy.issuers. Static + lazily created in the property source.
    private static TestIssuer brandX;
    private static TestIssuer brandY;

    @DynamicPropertySource
    static void tenancy(DynamicPropertyRegistry registry) {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        // Trusted set = two real per-brand issuers => multi-issuer mode (SecurityConfig
        // swaps onto the per-issuer resolver; an unknown iss 401s, fail-closed).
        registry.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        // Keep the lone back-compat issuer-uri pointed at brand-X (harmless; the
        // multi-issuer resolver is what validates, discovery-style, per iss).
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", brandX::issuerUri);
    }

    @AfterAll
    static void stopIssuers() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
    }

    @Autowired WebTestClient web;
    @Autowired DatabaseClient db;

    /** Each test stamps unique actor/target keys so the shared context's rows from
     *  sibling tests can never bleed into an assertion. */
    private String unique(String tag) { return tag + "-" + java.util.UUID.randomUUID(); }

    @BeforeEach
    void cleanTrail() {
        // The audit table is shared across this class's tests; truncate so per-test
        // counts are deterministic regardless of execution order.
        db.sql("DELETE FROM forum_action").fetch().rowsUpdated().block();
    }

    private WebTestClient.RequestHeadersSpec<?> getAudit(String bearer) {
        return web.get().uri("/bff/forum/admin/audit").headers(h -> h.setBearerAuth(bearer));
    }

    /** Drive a stubbed ban through the REAL chain (audits a domain-stamped row). */
    private void banAs(String bearer, String targetSubject) {
        web.post().uri("/bff/forum/admin/users/" + targetSubject + "/ban?reason=test")
                .headers(h -> h.setBearerAuth(bearer))
                .exchange()
                // Stubbed congruence => 202 pending-reconcile (never 200), but the row IS audited.
                .expectStatus().isAccepted();
    }

    // ── CROSS-USER DENY: brand-X admin never reads brand-Y's audit trail ──
    @Test
    void brandXAdmin_readsOnlyBrandXAudit_brandYInvisible() {
        String xTarget = unique("victim-x");
        String yTarget = unique("victim-y");

        // Brand-X admin bans -> a brandx-stamped row. Brand-Y admin bans -> a brandy row.
        banAs(brandX.mint("admin-x", List.of("admin")), xTarget);
        banAs(brandY.mint("admin-y", List.of("admin")), yTarget);

        // Brand-X admin's audit read sees its own target and NOT brand-Y's.
        getAudit(brandX.mint("admin-x", List.of("admin"))).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + xTarget + "')]").exists()
                .jsonPath("$.actions[?(@.target=='" + yTarget + "')]").doesNotExist()
                .jsonPath("$.actions[?(@.domain=='brandy')]").doesNotExist();

        // Symmetric: brand-Y admin sees only brand-Y's row.
        getAudit(brandY.mint("admin-y", List.of("admin"))).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + yTarget + "')]").exists()
                .jsonPath("$.actions[?(@.target=='" + xTarget + "')]").doesNotExist()
                .jsonPath("$.actions[?(@.domain=='brandx')]").doesNotExist();
    }

    // ── CROSS-USER DENY: a forged ?domain= request param cannot widen the scope ──
    @Test
    void requestParamDomain_isIgnored_issuerWins() {
        String xTarget = unique("victim-x");
        String yTarget = unique("victim-y");
        banAs(brandX.mint("admin-x", List.of("admin")), xTarget);
        banAs(brandY.mint("admin-y", List.of("admin")), yTarget);

        // Brand-X admin tries to read brand-Y's trail by FORGING a request param. The
        // domain is server-derived from the validated issuer, so the param is inert:
        // the read still returns ONLY brandx, never brandy.
        web.get().uri("/bff/forum/admin/audit?domain=brandy")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + xTarget + "')]").exists()
                .jsonPath("$.actions[?(@.target=='" + yTarget + "')]").doesNotExist()
                .jsonPath("$.actions[?(@.domain=='brandy')]").doesNotExist();
    }

    // ── MULTIUSER-SITUATIONAL: SUPERADMIN (cross-domain bypass) reads BOTH brands ──
    @Test
    void superadmin_readsEveryBrandsAudit() {
        String xTarget = unique("victim-x");
        String yTarget = unique("victim-y");
        banAs(brandX.mint("admin-x", List.of("admin")), xTarget);
        banAs(brandY.mint("admin-y", List.of("admin")), yTarget);

        // A SUPERADMIN minted by EITHER issuer is unscoped (PrincipalDomain returns null
        // for SUPERADMIN), so it sees both brands' rows.
        getAudit(brandX.mint("root", List.of("superadmin"))).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + xTarget + "')]").exists()
                .jsonPath("$.actions[?(@.target=='" + yTarget + "')]").exists()
                .jsonPath("$.actions[?(@.domain=='brandx')]").exists()
                .jsonPath("$.actions[?(@.domain=='brandy')]").exists();
    }

    // ── WRITE isolation: the ban a brand-X admin records is stamped brandx ──
    @Test
    void banRecordedByBrandXAdmin_isStampedBrandX_andHiddenFromBrandY() {
        String target = unique("victim");
        banAs(brandX.mint("admin-x", List.of("admin")), target);

        // Brand-Y admin (different issuer => brandy scope) cannot see the brandx row.
        getAudit(brandY.mint("admin-y", List.of("admin"))).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "')]").doesNotExist();

        // The recording brand-X admin can.
        getAudit(brandX.mint("admin-x", List.of("admin"))).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "')]").exists()
                .jsonPath("$.actions[?(@.target=='" + target + "' && @.domain=='brandx')]").exists();
    }
}
