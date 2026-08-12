package net.hugmesh.forumbff.forum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.config.SecurityConfig;
import net.hugmesh.forumbff.external.BlockOutcome;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;
import net.hugmesh.forumbff.web.ApiExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The ADMIN-only console seam ({@code /bff/forum/admin/**}). Asserts:
 * <ul>
 *   <li>an ADMIN WITHOUT ROLE_FORUM REACHES the seam (the path is ADMIN end-to-end so
 *       the user floor never blocks an admin);</li>
 *   <li>a ROLE_MOD+ROLE_FORUM user is FORBIDDEN (the admin seam is ADMIN-only — mods
 *       never touch /bff/forum/admin/**);</li>
 *   <li>a STUBBED ban returns 202 pending-reconcile (never 200) and is audited.</li>
 * </ul>
 */
@WebFluxTest(controllers = ForumAdminController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class ForumAdminControllerTest {

    // Spring Security 7: mockJwt()'s SecurityContext is only honoured when the
    // springSecurity() configurer's MutatorFilter is in the chain. The @WebFluxTest
    // slice's auto-configured WebTestClient lacks it (the mutator is dropped -> 401),
    // so build the client from the ApplicationContext with .apply(springSecurity()).
    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean PhpbbApiClient phpbb;
    @MockitoBean ForumService forum;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient asAdminNoForum() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asModForum() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_FORUM")));
    }

    @Test
    void stats_reachedByAdminWithoutForumRole() {
        when(phpbb.stats()).thenReturn(Mono.just(new ForumDto.Stats(12, 40, 5, 0, "live")));
        asAdminNoForum().get().uri("/bff/forum/admin/stats").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.topics").isEqualTo(12);
    }

    @Test
    void stats_forbiddenForModForumUser() {
        asModForum().get().uri("/bff/forum/admin/stats").exchange().expectStatus().isForbidden();
    }

    /** A STUBBED ban -> 202 pending-reconcile (NEVER 200) + a forum_action note. */
    @Test
    void ban_stubbedReturns202PendingReconcile() {
        when(forum.ban(eq("sub-99"), any(), any())).thenReturn(Mono.just(BlockOutcome.STUBBED));
        asAdminNoForum().post().uri("/bff/forum/admin/users/sub-99/ban?reason=abuse").exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.external").isEqualTo("stubbed")
                .jsonPath("$.subject").isEqualTo("sub-99");
    }

    @Test
    void unban_stubbedReturns202() {
        when(forum.unban(eq("sub-99"), any(), any())).thenReturn(Mono.just(BlockOutcome.STUBBED));
        asAdminNoForum().method(org.springframework.http.HttpMethod.DELETE)
                .uri("/bff/forum/admin/users/sub-99/ban").exchange()
                .expectStatus().isAccepted()
                .expectBody().jsonPath("$.op").isEqualTo("unban");
    }

    @Test
    void ban_forbiddenForModForumUser() {
        asModForum().post().uri("/bff/forum/admin/users/sub-99/ban").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void installStyle_adminOnly_audited() {
        when(phpbb.installStyle(eq("prosilver"))).thenReturn(Mono.empty());
        when(forum.recordInstall(any(), eq("admin.forum.style.install"), eq("prosilver")))
                .thenReturn(Mono.just(new ForumAction("a-1", "admin", "admin.forum.style.install",
                        "prosilver", "ok", "", java.time.Instant.now(), "default")));
        asAdminNoForum().post().uri("/bff/forum/admin/styles?name=prosilver").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("installed");
    }

    @Test
    void installStyle_forbiddenForModForumUser() {
        asModForum().post().uri("/bff/forum/admin/styles?name=prosilver").exchange()
                .expectStatus().isForbidden();
    }

    // ── PUT /users/{subject}/groups ────────────────────────────────────

    @Test
    void syncGroups_allowedForAdmin() {
        when(forum.syncGroups(any(), eq("sub-42"))).thenReturn(reactor.core.publisher.Mono.empty());
        asAdminNoForum().put().uri("/bff/forum/admin/users/sub-42/groups").exchange()
                .expectStatus().isOk();
    }

    @Test
    void syncGroups_forbiddenForUser() {
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .put().uri("/bff/forum/admin/users/sub-42/groups").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void syncGroups_forbiddenForAnonymous() {
        web.put().uri("/bff/forum/admin/users/sub-42/groups").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void audit_listReturnsActions_forAdmin() {
        // The controller reads the DOMAIN-SCOPED, server-CAPPED trail via the service
        // (brand-scoped; SUPERADMIN unscoped). No ?limit= -> the service clamps to the
        // default cap; the slice asserts the controller surfaces the bounded result.
        when(forum.auditTrail(any(), any())).thenReturn(reactor.core.publisher.Flux.just(
                new ForumAction("a-1", "admin", "admin.forum.user.ban", "sub-9", "stubbed", "abuse",
                        java.time.Instant.now(), "default")));
        asAdminNoForum().get().uri("/bff/forum/admin/audit").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions[0].action").isEqualTo("admin.forum.user.ban");
    }

    /** The optional ?limit= reaches the service as the (to-be-clamped) requested cap. */
    @Test
    void audit_passesRequestedLimit_toService() {
        when(forum.auditTrail(any(), org.mockito.ArgumentMatchers.eq(5)))
                .thenReturn(reactor.core.publisher.Flux.just(
                        new ForumAction("a-2", "admin", "admin.forum.user.ban", "sub-1", "ok", null,
                                java.time.Instant.now(), "default")));
        asAdminNoForum().get().uri("/bff/forum/admin/audit?limit=5").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions[0].target").isEqualTo("sub-1");
    }

    // ── the admin-bff PhpbbAdminClient contract surfaces (un-stub) ───────

    /** admin-bff sends ban {reason} as a JSON BODY (not ?reason=) — still 202 when stubbed. */
    @Test
    void ban_viaJsonBody_stubbedReturns202() {
        when(forum.ban(eq("sub-1"), eq("spam"), any())).thenReturn(Mono.just(BlockOutcome.STUBBED));
        asAdminNoForum().post().uri("/bff/forum/admin/users/sub-1/ban")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"spam\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.state").isEqualTo("pending-reconcile");
    }

    @Test
    void listUsers_admin_returnsEnvelope() {
        when(forum.listUsers(any())).thenReturn(reactor.core.publisher.Flux.just(
                new ForumDto.ForumUser("sub-1", 7L, "REGISTERED")));
        asAdminNoForum().get().uri("/bff/forum/admin/users").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.users[0].casdoorSubject").isEqualTo("sub-1");
    }

    @Test
    void listUsers_forbiddenForModForumUser() {
        asModForum().get().uri("/bff/forum/admin/users").exchange().expectStatus().isForbidden();
    }

    @Test
    void getUser_present_returns200() {
        when(forum.getUser(any(), eq("sub-1"))).thenReturn(Mono.just(
                new ForumDto.ForumUser("sub-1", 7L, "REGISTERED")));
        asAdminNoForum().get().uri("/bff/forum/admin/users/sub-1").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.casdoorSubject").isEqualTo("sub-1");
    }

    @Test
    void getUser_darkSeam_returns204() {
        when(forum.getUser(any(), eq("sub-x"))).thenReturn(Mono.empty());
        asAdminNoForum().get().uri("/bff/forum/admin/users/sub-x").exchange()
                .expectStatus().isNoContent();
    }

    // ── named group assignment (POST {group}) ───────────────────────────

    @Test
    void assignGroup_validGroup_allowed() {
        when(forum.assignGroup(any(), eq("sub-1"), eq("GLOBAL_MODERATORS"))).thenReturn(Mono.empty());
        asAdminNoForum().post().uri("/bff/forum/admin/users/sub-1/groups")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"group\":\"GLOBAL_MODERATORS\"}")
                .exchange().expectStatus().isOk();
    }

    @Test
    void assignGroup_blankGroup_400() {
        asAdminNoForum().post().uri("/bff/forum/admin/users/sub-1/groups")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"group\":\"\"}")
                .exchange().expectStatus().isBadRequest();
    }

    /** An unknown ForumGroup name is a 400 (IllegalArgumentException → BAD_REQUEST), not a 500. */
    @Test
    void assignGroup_unknownGroup_400() {
        when(forum.assignGroup(any(), eq("sub-1"), eq("SUPERUSERS")))
                .thenThrow(new IllegalArgumentException("No enum constant ForumGroup.SUPERUSERS"));
        asAdminNoForum().post().uri("/bff/forum/admin/users/sub-1/groups")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"group\":\"SUPERUSERS\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").isEqualTo("invalid group");
    }

    @Test
    void assignGroup_forbiddenForModForumUser() {
        asModForum().post().uri("/bff/forum/admin/users/sub-1/groups")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"group\":\"REGISTERED\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── category CRUD ───────────────────────────────────────────────────

    @Test
    void categories_admin_returnsEnvelope() {
        when(forum.listCategories(any())).thenReturn(reactor.core.publisher.Flux.just(
                new ForumDto.Category(1L, "General", "chat", 3)));
        asAdminNoForum().get().uri("/bff/forum/admin/categories").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.categories[0].name").isEqualTo("General");
    }

    @Test
    void createCategory_created_returns200() {
        when(forum.createCategory(any(), any())).thenReturn(Mono.just(new ForumDto.Category(9L, "Ops", "", 0)));
        asAdminNoForum().post().uri("/bff/forum/admin/categories")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"Ops\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("created").jsonPath("$.id").isEqualTo(9);
    }

    /** A DARK extension seam (empty Mono) → 202 pending-reconcile, never a 500/200-created. */
    @Test
    void createCategory_darkSeam_returns202() {
        when(forum.createCategory(any(), any())).thenReturn(Mono.empty());
        asAdminNoForum().post().uri("/bff/forum/admin/categories")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"Ops\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.state").isEqualTo("pending-reconcile");
    }

    @Test
    void createCategory_blankName_400() {
        asAdminNoForum().post().uri("/bff/forum/admin/categories")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"\"}")
                .exchange().expectStatus().isBadRequest();
    }

    // ── moderation queue (approve / reject) ─────────────────────────────

    @Test
    void moderationQueue_admin_returnsEnvelope() {
        when(forum.moderationQueue(any())).thenReturn(reactor.core.publisher.Flux.just(
                new ForumDto.QueueItem("q-1", 4L, "sub-9", "spam excerpt", "pending", java.time.Instant.now())));
        asAdminNoForum().get().uri("/bff/forum/admin/moderation-queue").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.queue[0].id").isEqualTo("q-1");
    }

    @Test
    void approve_admin_ok() {
        when(forum.approveQueued(any(), eq("q-1"))).thenReturn(Mono.empty());
        asAdminNoForum().post().uri("/bff/forum/admin/moderation/q-1/approve").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.action").isEqualTo("approve");
    }

    @Test
    void reject_admin_ok() {
        when(forum.rejectQueued(any(), eq("q-1"))).thenReturn(Mono.empty());
        asAdminNoForum().post().uri("/bff/forum/admin/moderation/q-1/reject").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.action").isEqualTo("reject");
    }

    @Test
    void approve_forbiddenForModForumUser() {
        asModForum().post().uri("/bff/forum/admin/moderation/q-1/approve").exchange()
                .expectStatus().isForbidden();
    }

    /** admin-bff sends style install {name} as a JSON BODY (not ?name=). */
    @Test
    void installStyle_viaJsonBody_ok() {
        when(phpbb.installStyle(eq("prosilver"))).thenReturn(Mono.empty());
        when(forum.recordInstall(any(), eq("admin.forum.style.install"), eq("prosilver")))
                .thenReturn(Mono.just(new ForumAction("a-1", "admin", "admin.forum.style.install",
                        "prosilver", "ok", "", java.time.Instant.now(), "default")));
        asAdminNoForum().post().uri("/bff/forum/admin/styles")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"prosilver\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("installed");
    }
}
