package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;

/**
 * THE no-ADMIN-implies-MOD EDGE asserted at the HTTP layer with REAL tokens (mission
 * item 3). {@link ModerationControllerTest} already pins this gate, but with
 * {@code mockJwt().authorities(...)} — hand-assembled Spring authorities that skip the
 * real Casdoor JWT → {@code ROLE_<UPPER>} conversion AND the issuer→domain wiring. This
 * class drives the REAL filter chain + REAL {@link ForumService} (its defence-in-depth
 * {@code assertModerator} re-check) authenticated by REAL RS256 tokens whose
 * {@code roles} claim the production converter maps — so the role MATRIX is proven
 * end-to-end, exactly as a browser token would be processed.
 *
 * <p>The load-bearing rule is the AND-of-(MOD,FORUM), NOT {@code hasAnyRole(MOD,ADMIN)}.
 * The role hierarchy is deliberately MINIMAL ({@code SUPERADMIN > ADMIN/MOD/USER} only;
 * NO {@code ADMIN > MOD} edge, NO MOD-AND-FORUM composite), so:
 * <ul>
 *   <li><b>ADMIN alone → ALLOWED</b> (the explicit OR branch; an admin moderates
 *       without holding MOD or FORUM);</li>
 *   <li><b>MOD without FORUM → 403</b> — THE EDGE: a bare MOD is NOT a forum moderator,
 *       and there is no hierarchy that lets it become one;</li>
 *   <li><b>FORUM without MOD → 403</b> — a plain forum user is not a moderator;</li>
 *   <li><b>MOD + FORUM → ALLOWED</b> (the AND is satisfied);</li>
 *   <li><b>plain USER → 403</b>;</li>
 *   <li><b>SUPERADMIN → ALLOWED</b> at moderation — the platform cascade
 *       {@code SUPERADMIN ≥ ADMIN ≥ MOD ≥ USER}. A SUPERADMIN passes the
 *       {@code @PreAuthorize} gate via the hierarchy ({@code ROLE_SUPERADMIN >
 *       ROLE_ADMIN}) AND the controller's {@code ForumService.assertModerator}
 *       defence-in-depth re-check, which is now HIERARCHY-AWARE ({@code isAdmin} honours
 *       the SUPERADMIN super-role). This makes {@code /moderation} consistent with the
 *       strictly-more-privileged {@code /bff/forum/admin/**} seam the same SUPERADMIN
 *       reaches (asserted ALLOWED in {@code ForumAdminSuperadminAccessTest}) — i.e. the
 *       wave-2 discrepancy (200 at {@code /admin}, 403 at {@code /moderation}) is FIXED.
 *       The cascade is NOT broadened: a bare MOD-without-FORUM and a plain USER are still
 *       403, and domain-scoping is unchanged.</li>
 * </ul>
 * Both the read ({@code GET /moderation/queue}) and the write
 * ({@code POST /moderation/topics/{id}}) are asserted so the matrix holds across verbs.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ForumRoleMatrixHttpTest extends PostgresTestSupport {

    private static TestIssuer issuer;

    @DynamicPropertySource
    static void tenancy(DynamicPropertyRegistry registry) {
        // Two listed issuers => multi-issuer mode (real per-issuer resolver). We mint
        // from brandx for the whole matrix; the second entry just keeps the registry
        // genuinely multi-issuer so the resolver path (not the o.jwt back-compat) is exercised.
        issuer = new TestIssuer();
        try (TestIssuer other = new TestIssuer()) {
            registry.add("app.tenancy.issuers",
                    () -> issuer.issuerUri() + "=brandx," + other.issuerUri() + "=brandy");
        }
        // 'other' only needs to contribute its URI to the registry CSV string; the
        // matrix never mints from it, so closing it immediately is fine (no token of
        // that issuer is ever validated).
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", issuer::issuerUri);
    }

    @AfterAll
    static void stopIssuer() {
        if (issuer != null) issuer.close();
    }

    @Autowired WebTestClient web;

    private String token(String... roles) {
        return issuer.mint("u-" + String.join("-", roles), List.of(roles));
    }

    private void expectQueue(int expected, String... roles) {
        web.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(token(roles)))
                .exchange()
                .expectStatus().value(s -> org.assertj.core.api.Assertions.assertThat(s).isEqualTo(expected));
    }

    private void expectModerate(int expected, String... roles) {
        web.post().uri("/bff/forum/moderation/topics/7")
                .headers(h -> h.setBearerAuth(token(roles)))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"action\":\"lock\",\"reason\":\"spam\"}")
                .exchange()
                .expectStatus().value(s -> org.assertj.core.api.Assertions.assertThat(s).isEqualTo(expected));
    }

    // ── ALLOW: ADMIN alone moderates (the OR branch — no MOD/FORUM needed) ──
    @Test
    void admin_alone_allowed_read() {
        // Stub seam => stats() returns the degraded typed fallback; the queue endpoint
        // still returns 200 with a queueDepth. What matters is the 200, not the value.
        expectQueue(200, "admin");
    }

    @Test
    void admin_alone_allowed_write() {
        expectModerate(200, "admin");
    }

    // ── THE EDGE: MOD WITHOUT FORUM is NOT a moderator -> 403 ──
    @Test
    void modWithoutForum_forbidden_read() {
        expectQueue(403, "mod");
    }

    @Test
    void modWithoutForum_forbidden_write() {
        expectModerate(403, "mod");
    }

    // ── FORUM WITHOUT MOD is NOT a moderator -> 403 ──
    @Test
    void forumWithoutMod_forbidden_read() {
        expectQueue(403, "forum");
    }

    @Test
    void forumWithoutMod_forbidden_write() {
        expectModerate(403, "forum");
    }

    // ── ALLOW: MOD AND FORUM satisfies the AND ──
    @Test
    void modAndForum_allowed_read() {
        expectQueue(200, "mod", "forum");
    }

    @Test
    void modAndForum_allowed_write() {
        expectModerate(200, "mod", "forum");
    }

    // ── plain USER -> 403 ──
    @Test
    void plainUser_forbidden_read() {
        // A token with NO roles still floors to ROLE_USER (the converter) -> authenticated
        // but not a moderator -> 403.
        web.get().uri("/bff/forum/moderation/queue")
                .headers(h -> h.setBearerAuth(issuer.mint("plain", List.of())))
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── SUPERADMIN at moderation -> 200 (cascade-aware; the wave-2 discrepancy FIXED) ──
    @Test
    void superadmin_atModeration_allowed_byCascade() {
        // CASCADE: a SUPERADMIN token (authorities ROLE_USER + ROLE_SUPERADMIN + DOMAIN_x,
        // NO raw ROLE_ADMIN) PASSES the @PreAuthorize("hasRole('ADMIN') or ...") method
        // gate via the SecurityConfig role hierarchy (ROLE_SUPERADMIN > ROLE_ADMIN), AND
        // the controller's defence-in-depth ForumService.assertModerator(auth) re-check —
        // now HIERARCHY-AWARE: ForumService.isAdmin honours the SUPERADMIN super-role
        // (Roles.isSuperadmin), so a SUPERADMIN early-returns just like an ADMIN. This
        // makes /moderation consistent with the strictly-more-privileged
        // /bff/forum/admin/** seam the SAME SUPERADMIN reaches (asserted ALLOWED in
        // ForumAdminSuperadminAccessTest). This FLIPS the wave-2 pin
        // (superadmin_atModeration_forbidden_byServiceRecheck, which asserted the
        // inconsistent 403) now that the discrepancy is fixed in prod.
        expectQueue(200, "superadmin");
    }

    @Test
    void superadmin_atModeration_allowed_byCascade_write() {
        expectModerate(200, "superadmin");
    }

    // ── ALLOW: ADMIN at moderation (write) — the explicit OR branch, cascade above MOD ──
    @Test
    void admin_atModeration_allowed_write_explicit() {
        // ADMIN already passed assertModerator pre-fix (raw ROLE_ADMIN early-return);
        // asserted here to pin the full cascade row (SUPERADMIN ≥ ADMIN both ALLOWED).
        expectModerate(200, "admin");
    }

    // ── unauthenticated -> 401 (the path floor is .authenticated()) ──
    @Test
    void unauthenticated_401() {
        web.get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isUnauthorized();
    }
}
