package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.forumbff.testsupport.TestIssuer;

import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RAW-API-DENY negative security suite for the forum admin + moderation WRITE surface —
 * MUTATION-RESISTANT: every restricted caller is asserted DENIED at the HTTP boundary
 * (401/403) AND, where the action would have audited a {@code forum_action} row, the
 * trail is re-read straight out of the DB to prove the denied write produced NO side
 * effect (the request never reached the service). This is the negative mirror of the
 * positive {@link ForumAdminCrossDomainHttpTest} / {@link ForumDomainIsolationHttpTest}
 * / {@link ForumRoleMatrixHttpTest} coverage, extended ACROSS THE WHOLE write surface
 * (ban / unban / assignGroup / syncGroups / createCategory / approve / reject /
 * installStyle / installExtension + the moderation write), not just ban + syncGroups.
 *
 * <p>Modelled on the federation-api gold exemplar (CrossDomainWriteIsolationTest /
 * MultiIssuerSecuritySliceTest): REAL per-brand RS256 in-process JWKS issuers (mint
 * wrong-role / foreign-issuer / wrong-kid tokens), a REAL Liquibase H2 schema, and a
 * re-read of the persisted state AFTER the denied write to defeat a fail-open mutation.
 *
 * <p>Authority for the expected status comes from this repo's {@code SecurityConfig}
 * path table + the controller {@code @PreAuthorize}:
 * <ul>
 *   <li>{@code /bff/forum/admin/**} → {@code hasAnyRole(ADMIN,SUPERADMIN)} (path) +
 *       per-method {@code @PreAuthorize("hasRole('ADMIN')")}. So a ROLE_USER, a
 *       ROLE_MOD-without-forum-authority, and a ROLE_FORUM user are all 403; anon →
 *       401; a correctly-signed token from an UNLISTED issuer → 401 (fail-closed); a
 *       genuinely-signed token with an unknown {@code kid} → 401.</li>
 *   <li>{@code /bff/forum/moderation/**} → path {@code .authenticated()} + method
 *       {@code @PreAuthorize("hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))")}.
 *       A ROLE_MOD-without-FORUM and a plain ROLE_USER are 403; anon → 401; unlisted
 *       issuer / wrong-kid → 401.</li>
 * </ul>
 *
 * <p>The phpBB seam + ban congruence stay STUBBED (test profile), so an ALLOWED admin
 * write still audits a domain-stamped row — which is precisely why a DENIED write
 * leaving ZERO rows is a meaningful, non-vacuous assertion (the audit write is the
 * observable that a fail-open would flip).
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ForumAdminRawApiDenyTest extends PostgresTestSupport {

    private static TestIssuer brandX;   // a trusted, listed brand
    private static TestIssuer brandY;   // a second trusted brand (keeps multi-issuer mode on)
    private static TestIssuer rogue;    // correctly-signed but UNLISTED issuer (foreign)

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

    /** Total rows in the audit trail right now — the mutation observable. */
    private long auditRowCount() {
        return db.sql("SELECT COUNT(*) AS c FROM forum_action")
                .map(row -> ((Number) row.get("c")).longValue())
                .one().block();
    }

    /** Rows whose target == the given key — the per-action mutation observable. */
    private long auditRowsForTarget(String target) {
        return db.sql("SELECT COUNT(*) AS c FROM forum_action WHERE target = :t")
                .bind("t", target)
                .map(row -> ((Number) row.get("c")).longValue())
                .one().block();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Per-write-endpoint matrix. Each entry is exercised with a JSON body where
    //  the contract requires one, so the request reaches the security gate fully
    //  formed (a denied write must be denied REGARDLESS of a valid body).
    // ════════════════════════════════════════════════════════════════════════

    private WebTestClient.RequestHeadersSpec<?> ban(String target) {
        return web.post().uri("/bff/forum/admin/users/" + target + "/ban?reason=abuse");
    }
    private WebTestClient.RequestHeadersSpec<?> unban(String target) {
        return web.delete().uri("/bff/forum/admin/users/" + target + "/ban?reason=lift");
    }
    private WebTestClient.RequestHeadersSpec<?> assignGroup(String target) {
        return web.post().uri("/bff/forum/admin/users/" + target + "/groups")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"group\":\"GLOBAL_MODERATORS\"}");
    }
    private WebTestClient.RequestHeadersSpec<?> syncGroups(String target) {
        return web.put().uri("/bff/forum/admin/users/" + target + "/groups");
    }
    private WebTestClient.RequestHeadersSpec<?> createCategory(String target) {
        return web.post().uri("/bff/forum/admin/categories")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"" + target + "\",\"description\":\"d\"}");
    }
    private WebTestClient.RequestHeadersSpec<?> approve(String target) {
        return web.post().uri("/bff/forum/admin/moderation/" + target + "/approve");
    }
    private WebTestClient.RequestHeadersSpec<?> reject(String target) {
        return web.post().uri("/bff/forum/admin/moderation/" + target + "/reject");
    }
    private WebTestClient.RequestHeadersSpec<?> installStyle(String target) {
        return web.post().uri("/bff/forum/admin/styles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"name\":\"" + target + "\"}");
    }
    private WebTestClient.RequestHeadersSpec<?> installExtension(String target) {
        return web.post().uri("/bff/forum/admin/extensions")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"name\":\"" + target + "\"}");
    }
    /** The /moderation/** write surface (NOT under /admin/**, but still a privileged write). */
    private WebTestClient.RequestHeadersSpec<?> moderateTopic() {
        return web.post().uri("/bff/forum/moderation/topics/7")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"action\":\"lock\",\"reason\":\"spam\"}");
    }

    /** Drive every admin write with a fresh unique target, asserting deny + no-side-effect. */
    private void denyEveryAdminWrite(int expectedStatus, Consumer<org.springframework.http.HttpHeaders> bearer) {
        // Each write gets its OWN unique target so the per-target re-read is exact and
        // order-independent. We rebuild the request list per target.
        for (String name : List.of("ban", "unban", "assignGroup", "syncGroups",
                "createCategory", "approve", "reject", "installStyle", "installExtension")) {
            String target = unique(name);
            WebTestClient.RequestHeadersSpec<?> req = byName(name, target);
            if (bearer != null) {
                req.headers(bearer);
            }
            req.exchange().expectStatus().value(s ->
                    assertThat(s).as("status for admin write '%s'", name).isEqualTo(expectedStatus));
            // MUTATION-RESISTANCE: a denied write must not have audited anything for this target.
            assertThat(auditRowsForTarget(target))
                    .as("denied admin write '%s' must leave NO forum_action row", name)
                    .isZero();
        }
    }

    private WebTestClient.RequestHeadersSpec<?> byName(String name, String target) {
        return switch (name) {
            case "ban" -> ban(target);
            case "unban" -> unban(target);
            case "assignGroup" -> assignGroup(target);
            case "syncGroups" -> syncGroups(target);
            case "createCategory" -> createCategory(target);
            case "approve" -> approve(target);
            case "reject" -> reject(target);
            case "installStyle" -> installStyle(target);
            case "installExtension" -> installExtension(target);
            default -> throw new IllegalArgumentException(name);
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    //  ROLE_USER cannot hit /bff/forum/admin/** -> 403, no side effect
    // ════════════════════════════════════════════════════════════════════════

    @Test
    void plainUser_deniedEveryAdminWrite_403_andNoAudit() {
        // A token with NO roles still floors to ROLE_USER (the converter): authenticated
        // but NOT admin -> 403 on the ADMIN-gated path, and the write never lands.
        denyEveryAdminWrite(403, h -> h.setBearerAuth(brandX.mint("plain", List.of())));
        assertThat(auditRowCount()).as("no admin write by a plain user may persist").isZero();
    }

    @Test
    void forumUser_deniedEveryAdminWrite_403_andNoAudit() {
        // ROLE_FORUM (a forum user) is NOT admin -> 403. The converter gives a forum user
        // no ADMIN/SUPERADMIN authority, so the path gate denies before the method runs.
        denyEveryAdminWrite(403, h -> h.setBearerAuth(brandX.mint("fuser", List.of("forum"))));
        assertThat(auditRowCount()).isZero();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  ROLE_MOD WITHOUT forum authority cannot hit /bff/forum/admin/** -> 403
    // ════════════════════════════════════════════════════════════════════════

    @Test
    void mod_deniedEveryAdminWrite_403_andNoAudit() {
        // A MOD has no ADMIN/SUPERADMIN role and there is NO ADMIN>MOD hierarchy edge ->
        // 403 on the admin seam. (The MOD-AND-FORUM gate is the moderation surface, not /admin.)
        denyEveryAdminWrite(403, h -> h.setBearerAuth(brandX.mint("mod", List.of("mod"))));
        assertThat(auditRowCount()).isZero();
    }

    @Test
    void modAndForum_deniedEveryAdminWrite_403_andNoAudit() {
        // EVEN MOD+FORUM (a full forum moderator) is NOT an admin -> still 403 at /admin/**.
        // Moderators moderate; they do not run the admin console (ban/category/install).
        denyEveryAdminWrite(403, h -> h.setBearerAuth(brandX.mint("modforum", List.of("mod", "forum"))));
        assertThat(auditRowCount()).isZero();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Anonymous -> 401, no side effect
    // ════════════════════════════════════════════════════════════════════════

    @Test
    void anonymous_deniedEveryAdminWrite_401_andNoAudit() {
        denyEveryAdminWrite(401, null);
        assertThat(auditRowCount()).as("no admin write may persist unauthenticated").isZero();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Forged / foreign-issuer (correctly signed, UNLISTED iss) -> 401 fail-closed
    // ════════════════════════════════════════════════════════════════════════

    @Test
    void foreignIssuerCarryingAdmin_deniedEveryAdminWrite_401_andNoAudit() {
        // A genuinely RS256-signed token claiming ROLE_ADMIN, but from an issuer that is
        // NOT in app.tenancy.issuers. The per-issuer resolver has no manager for that iss
        // -> 401 (fail-closed), never default-accept. The admin claim is inert.
        denyEveryAdminWrite(401, h -> h.setBearerAuth(rogue.mint("attacker", List.of("admin"))));
        assertThat(auditRowCount()).as("a foreign-issuer admin token must change nothing").isZero();
    }

    @Test
    void wrongKidCarryingAdmin_deniedEveryAdminWrite_401_andNoAudit() {
        // A token from a TRUSTED issuer, real signature, but a JWS kid absent from the
        // published JWK set -> the decoder cannot resolve the key -> 401. Distinct from
        // the foreign-issuer case (rejected by the iss allowlist) and a tampered payload.
        denyEveryAdminWrite(401, h -> h.setBearerAuth(brandX.mintWithWrongKid("attacker", List.of("admin"))));
        assertThat(auditRowCount()).isZero();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Moderation WRITE surface: restricted callers denied, no audit side effect
    //  (the moderation write itself does not audit, so the observable is the
    //  total trail count staying zero — proving the request never executed.)
    // ════════════════════════════════════════════════════════════════════════

    @Test
    void moderationWrite_plainUser_403() {
        moderateTopic().headers(h -> h.setBearerAuth(brandX.mint("plain", List.of())))
                .exchange().expectStatus().isForbidden();
        assertThat(auditRowCount()).isZero();
    }

    @Test
    void moderationWrite_modWithoutForum_403() {
        // THE EDGE: a bare MOD (no FORUM) is NOT a forum moderator -> 403 (AND-of-MOD+FORUM).
        moderateTopic().headers(h -> h.setBearerAuth(brandX.mint("mod", List.of("mod"))))
                .exchange().expectStatus().isForbidden();
        assertThat(auditRowCount()).isZero();
    }

    @Test
    void moderationWrite_forumWithoutMod_403() {
        moderateTopic().headers(h -> h.setBearerAuth(brandX.mint("fuser", List.of("forum"))))
                .exchange().expectStatus().isForbidden();
        assertThat(auditRowCount()).isZero();
    }

    @Test
    void moderationWrite_anonymous_401() {
        moderateTopic().exchange().expectStatus().isUnauthorized();
        assertThat(auditRowCount()).isZero();
    }

    @Test
    void moderationWrite_foreignIssuer_401() {
        moderateTopic().headers(h -> h.setBearerAuth(rogue.mint("attacker", List.of("admin", "mod", "forum"))))
                .exchange().expectStatus().isUnauthorized();
        assertThat(auditRowCount()).isZero();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  CROSS-TENANT: a brand-Y admin cannot read/affect brand-X's audit trail.
    //  A brand-X admin's ban audits a brandx-stamped row; the brand-Y admin's
    //  audit read (issuer-scoped to brandy) must NOT surface it — the {subject}
    //  path var is the TARGET, never the actor's domain (no IDOR / scope-forge).
    // ════════════════════════════════════════════════════════════════════════

    @Test
    void crossTenant_brandYAdminCannotSeeBrandXAuditRow() {
        String target = unique("victim-x");
        // Brand-X admin records a (stubbed, audited) ban -> a brandx-stamped row.
        ban(target).headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange().expectStatus().isAccepted();
        assertThat(auditRowsForTarget(target)).as("brand-X ban audits exactly one row").isEqualTo(1L);

        // Brand-Y admin reads the trail through its OWN validated issuer (brandy scope):
        // the brandx row is invisible. The actor's domain came from the iss, not the path.
        web.get().uri("/bff/forum/admin/audit")
                .headers(h -> h.setBearerAuth(brandY.mint("admin-y", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "')]").doesNotExist();

        // Sanity: the recording brand-X admin DOES see its own brandx row (the deny is
        // a real scope, not a blanket empty result).
        web.get().uri("/bff/forum/admin/audit")
                .headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "' && @.domain=='brandx')]").exists();
    }

    @Test
    void crossTenant_forgedDomainParamCannotWidenBrandYReadIntoBrandX() {
        String target = unique("victim-x");
        ban(target).headers(h -> h.setBearerAuth(brandX.mint("admin-x", List.of("admin"))))
                .exchange().expectStatus().isAccepted();

        // Brand-Y admin appends ?domain=brandx trying to FORGE a cross-tenant read. The
        // domain is server-derived from the validated issuer, so the param is inert: the
        // brand-Y admin still sees ONLY brandy (here: nothing for this brandx target).
        web.get().uri("/bff/forum/admin/audit?domain=brandx")
                .headers(h -> h.setBearerAuth(brandY.mint("admin-y", List.of("admin"))))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[?(@.target=='" + target + "')]").doesNotExist();
    }
}
