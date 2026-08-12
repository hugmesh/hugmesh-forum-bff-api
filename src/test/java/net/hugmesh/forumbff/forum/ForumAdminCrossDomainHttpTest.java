package net.hugmesh.forumbff.forum;

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
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;

/**
 * The ADMIN-ONLY congruence endpoints — {@code POST/DELETE /bff/forum/admin/users/{subject}/ban}
 * and {@code PUT /bff/forum/admin/users/{subject}/groups} (syncGroups) — exercised
 * THROUGH the production filter chain + REAL {@link ForumService} + REAL repositories
 * over a REAL schema, authenticated by REAL per-brand RS256 tokens (mission item 2).
 * Two orthogonal properties, both asserted at the HTTP boundary:
 *
 * <ul>
 *   <li><b>ROLE GATE</b> — these are {@code hasAnyRole(ADMIN,SUPERADMIN)} (path) +
 *       {@code @PreAuthorize("hasRole('ADMIN')")} (method). At HTTP: unauthenticated →
 *       401; an authenticated NON-admin (forum/mod) → 403; an UNKNOWN issuer → 401
 *       fail-closed; ADMIN → 202 (stubbed congruence, audited).</li>
 *   <li><b>CROSS-DOMAIN DENY</b> — the audit row a brand-X admin's ban / syncGroups
 *       writes is stamped from the brand-X ISSUER (never a request field), so a brand-Y
 *       admin can NEVER read it back through {@code GET /bff/forum/admin/audit}. The
 *       {@code {subject}} path variable identifies the TARGET user; it does NOT (and
 *       cannot) move the actor's domain.</li>
 * </ul>
 *
 * <p>The phpBB extension + ban congruence stay STUBBED (test profile), so ban → 202
 * pending-reconcile and syncGroups → 200, both still auditing a domain-stamped row —
 * which is what lets the cross-domain audit-isolation be asserted offline.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ForumAdminCrossDomainHttpTest extends PostgresTestSupport {

    private static TestIssuer brandX;
    private static TestIssuer brandY;
    private static TestIssuer rogue;   // correctly-signed but UNLISTED issuer

    @DynamicPropertySource
    static void tenancy(DynamicPropertyRegistry registry) {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();   // deliberately NOT in app.tenancy.issuers
        registry.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", brandX::issuerUri);
    }

    @AfterAll
    static void stopIssuers() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
        if (rogue != null) rogue.close();
    }

    @Autowired WebTestClient web;
    @Autowired DatabaseClient db;

    private String unique(String tag) { return tag + "-" + java.util.UUID.randomUUID(); }

    @BeforeEach
    void cleanTrail() {
        db.sql("DELETE FROM forum_action").fetch().rowsUpdated().block();
    }

    // ════════ ban: role gate at HTTP ════════════════════════════════════════

    @Test
    void ban_unauthenticated_401() {
        web.post().uri("/bff/forum/admin/users/sub-1/ban").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void ban_forumUserWithoutAdmin_403() {
        web.post().uri("/bff/forum/admin/users/sub-1/ban")
                .headers(h -> h.setBearerAuth(brandX.mint("u", List.of("forum"))))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void ban_modWithoutAdmin_403() {
        // The no-ADMIN-implies-MOD sibling property's mirror image: a MOD (even MOD+FORUM)
        // is NOT an admin (no ADMIN/SUPERADMIN role, no hierarchy edge) -> denied the admin seam.
        web.post().uri("/bff/forum/admin/users/sub-1/ban")
                .headers(h -> h.setBearerAuth(brandX.mint("m", List.of("mod", "forum"))))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void ban_unknownIssuer_failsClosed_401() {
        // A correctly-signed token from an UNLISTED issuer carrying admin -> 401 (the
        // per-issuer resolver returns Mono.empty() for an untrusted iss; never default-accept).
        web.post().uri("/bff/forum/admin/users/sub-1/ban")
                .headers(h -> h.setBearerAuth(rogue.mint("attacker", List.of("admin"))))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void ban_admin_202_andAudited() {
        String target = unique("victim");
        web.post().uri("/bff/forum/admin/users/" + target + "/ban?reason=abuse")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.op").isEqualTo("ban")
                .jsonPath("$.subject").isEqualTo(target);
    }

    // ════════ ban: cross-domain audit isolation ═════════════════════════════

    @Test
    void banAuditedByBrandX_isInvisibleToBrandYAdmin() {
        String target = unique("victim");
        web.post().uri("/bff/forum/admin/users/" + target + "/ban?reason=abuse")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange().expectStatus().isAccepted();

        // Brand-Y admin (a DIFFERENT validated issuer => brandy scope) cannot read the
        // brandx-stamped ban row. The {subject} path var was the TARGET, not the actor's domain.
        web.get().uri("/bff/forum/admin/audit")
                .headers(h -> h.setBearerAuth(brandY.mint("admin-y", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "')]").doesNotExist();

        // Brand-X admin can, and the row is stamped brandx.
        web.get().uri("/bff/forum/admin/audit")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "' && @.domain=='brandx')]").exists()
                .jsonPath("$.actions[?(@.action=='admin.forum.user.ban' && @.target=='" + target + "')]").exists();
    }

    // ════════ syncGroups: role gate + cross-domain audit isolation ══════════

    @Test
    void syncGroups_unauthenticated_401() {
        web.put().uri("/bff/forum/admin/users/sub-1/groups").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void syncGroups_forumUserWithoutAdmin_403() {
        web.put().uri("/bff/forum/admin/users/sub-1/groups")
                .headers(h -> h.setBearerAuth(brandX.mint("u", List.of("forum"))))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void syncGroups_unknownIssuer_failsClosed_401() {
        web.put().uri("/bff/forum/admin/users/sub-1/groups")
                .headers(h -> h.setBearerAuth(rogue.mint("attacker", List.of("admin"))))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void syncGroups_admin_200_andAuditedInActorBrand() {
        String target = unique("target");
        web.put().uri("/bff/forum/admin/users/" + target + "/groups")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange()
                .expectStatus().isOk();

        // The sync-groups action is audited; a brand-Y admin can NOT see the brandx row.
        web.get().uri("/bff/forum/admin/audit")
                .headers(h -> h.setBearerAuth(brandY.mint("admin-y", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.action=='admin.forum.user.sync-groups' && @.target=='"
                        + target + "')]").doesNotExist();

        // The actor's own brand sees it (stamped brandx).
        web.get().uri("/bff/forum/admin/audit")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.action=='admin.forum.user.sync-groups' && @.target=='"
                        + target + "' && @.domain=='brandx')]").exists();
    }
}
