package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.forumbff.config.SecurityConfig;
import systems.hugmesh.forumbff.phpbb.PhpbbApiClient;
import systems.hugmesh.forumbff.web.ApiExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Forum user-surface gating + contract (reactive @WebFluxTest). The story under test:
 * a plain ROLE_USER (no ROLE_FORUM) is FORBIDDEN; a ROLE_FORUM user is ALLOWED; an
 * ADMIN is ALLOWED (no ROLE_FORUM needed — the converter gives admins ROLE_ADMIN and
 * the method gate is FORUM-or-ADMIN). @PreAuthorize is active via
 * @EnableReactiveMethodSecurity in the imported SecurityConfig.
 */
@WebFluxTest(controllers = ForumController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class ForumControllerTest {

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

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asForum() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_FORUM")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    // ── categories ─────────────────────────────────────────────────────
    @Test
    void categories_allowedForForumUser() {
        when(phpbb.listCategories()).thenReturn(Flux.just(new ForumDto.Category(1, "General", "", 3)));
        asForum().get().uri("/bff/forum/categories").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.categories[0].name").isEqualTo("General");
    }

    @Test
    void categories_allowedForAdmin_withoutForumRole() {
        when(phpbb.listCategories()).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/forum/categories").exchange().expectStatus().isOk();
    }

    @Test
    void categories_forbiddenForPlainUserWithoutForumRole() {
        asUser().get().uri("/bff/forum/categories").exchange().expectStatus().isForbidden();
    }

    // ── create topic ───────────────────────────────────────────────────
    @Test
    void createTopic_allowedForForumUser_ensuresUserAndCreates() {
        when(forum.ensureUser(any())).thenReturn(Mono.just(new ForumDto.ForumUser("sub-1", 10L, "REGISTERED")));
        when(phpbb.createTopic(any())).thenReturn(Mono.just(
                new ForumDto.Topic(5, 1, "Hello", "sub-1", 0, Instant.parse("2026-06-11T00:00:00Z"))));
        asForum().post().uri("/bff/forum/topics").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"categoryId\":1,\"title\":\"Hello\",\"body\":\"hi there\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.topic.title").isEqualTo("Hello");
    }

    @Test
    void createTopic_400WhenMissingTitle() {
        asForum().post().uri("/bff/forum/topics").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"categoryId\":1,\"body\":\"hi\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void createTopic_forbiddenForPlainUser() {
        asUser().post().uri("/bff/forum/topics").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"categoryId\":1,\"title\":\"x\",\"body\":\"y\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── topic + replies ────────────────────────────────────────────────
    @Test
    void topic_returnsTopicAndReplies_forForumUser() {
        when(phpbb.getTopic(5L)).thenReturn(Mono.just(
                new ForumDto.Topic(5, 1, "Hello", "sub-1", 1, Instant.parse("2026-06-11T00:00:00Z"))));
        when(phpbb.listReplies(5L)).thenReturn(Flux.just(
                new ForumDto.Reply(9, 5, "sub-2", "nice", Instant.parse("2026-06-11T01:00:00Z"))));
        asForum().get().uri("/bff/forum/topics/5").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.topic.title").isEqualTo("Hello")
                .jsonPath("$.replies[0].body").isEqualTo("nice");
    }

    // ── reply ──────────────────────────────────────────────────────────
    @Test
    void reply_forbiddenForPlainUser() {
        asUser().post().uri("/bff/forum/topics/5/replies").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"body\":\"hi\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── delete post (FAIL-CLOSED, wrong-object-proof ownership gate) ───
    @Test
    // USER-SITUATIONAL: forum user deletes their OWN post — the gate resolves /posts/{id},
    // isOwnerOrAdmin passes, and the delete runs (seam enabled).
    void deletePost_allowedForOwner() {
        when(phpbb.isEnabled()).thenReturn(true);
        when(phpbb.getPost(7L)).thenReturn(Mono.just(
                new ForumDto.Reply(7, 1, "sub-owner", "body", Instant.parse("2026-06-11T00:00:00Z"))));
        when(forum.isOwnerOrAdmin(eq("sub-owner"), any())).thenReturn(true);
        when(phpbb.deletePost(7L)).thenReturn(Mono.empty());
        asForum().delete().uri("/bff/forum/posts/7").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deleted").isEqualTo(7);
    }

    @Test
    // CROSS-USER (ALLOW control via ADMIN override): a non-owner ADMIN may delete — the
    // gate still resolves the real post but isOwnerOrAdmin passes on ROLE_ADMIN.
    void deletePost_allowedForAdminOverride() {
        when(phpbb.isEnabled()).thenReturn(true);
        when(phpbb.getPost(7L)).thenReturn(Mono.just(
                new ForumDto.Reply(7, 1, "sub-other", "body", Instant.parse("2026-06-11T00:00:00Z"))));
        when(forum.isOwnerOrAdmin(eq("sub-other"), any())).thenReturn(true); // ROLE_ADMIN -> true
        when(phpbb.deletePost(7L)).thenReturn(Mono.empty());
        asAdmin().delete().uri("/bff/forum/posts/7").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deleted").isEqualTo(7);
    }

    @Test
    // CROSS-USER DENY: forum user tries to delete ANOTHER user's post — the gate denies with
    // 403 and the destructive deletePost is NEVER invoked (fail-closed, not a doOnNext+then).
    void deletePost_forbiddenForNonOwner_andWriteNeverRuns() {
        when(phpbb.isEnabled()).thenReturn(true);
        when(phpbb.getPost(7L)).thenReturn(Mono.just(
                new ForumDto.Reply(7, 1, "sub-other", "body", Instant.parse("2026-06-11T00:00:00Z"))));
        when(forum.isOwnerOrAdmin(eq("sub-other"), any())).thenReturn(false);
        // Stub deletePost so that IF the chain ever (wrongly) reached the write, the test still
        // executes — then assert below that it was NOT called.
        when(phpbb.deletePost(anyLong())).thenReturn(Mono.empty());
        asForum().delete().uri("/bff/forum/posts/7").exchange().expectStatus().isForbidden();
        verify(phpbb, never()).deletePost(anyLong());
    }

    @Test
    // FAIL-CLOSED on EMPTY resolve (the original fail-OPEN bug): the seam is enabled but the
    // post resolve emits empty (missing post / breaker-open degraded fallback). The OLD code
    // fell through to the write on empty; now it is a hard 404 and deletePost is NEVER called.
    void deletePost_emptyResolveDenied_writeNeverRuns() {
        when(phpbb.isEnabled()).thenReturn(true);
        when(phpbb.getPost(7L)).thenReturn(Mono.empty());      // not found / degraded
        when(phpbb.deletePost(anyLong())).thenReturn(Mono.empty());
        asForum().delete().uri("/bff/forum/posts/7").exchange().expectStatus().isNotFound();
        verify(phpbb, never()).deletePost(anyLong());
    }

    // ── edit post (FAIL-CLOSED, wrong-object-proof ownership gate) ─────
    @Test
    // USER-SITUATIONAL (ALLOW): forum user edits their OWN post — owner gate passes, edit runs.
    void editPost_allowedForOwner() {
        when(phpbb.isEnabled()).thenReturn(true);
        when(phpbb.getPost(42L)).thenReturn(Mono.just(
                new ForumDto.Reply(42, 1, "sub-1", "old", Instant.parse("2026-06-11T00:00:00Z"))));
        when(forum.isOwnerOrAdmin(eq("sub-1"), any())).thenReturn(true);
        when(phpbb.editPost(eq(42L), any())).thenReturn(Mono.just(
                new ForumDto.Reply(42, 1, "sub-1", "new content", Instant.parse("2026-06-11T02:00:00Z"))));
        asForum().put().uri("/bff/forum/posts/42").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"body\":\"new content\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.post.body").isEqualTo("new content");
    }

    @Test
    // CROSS-USER DENY: forum user tries to edit ANOTHER user's post — 403, editPost never runs.
    void editPost_forbiddenForNonOwner_andWriteNeverRuns() {
        when(phpbb.isEnabled()).thenReturn(true);
        when(phpbb.getPost(42L)).thenReturn(Mono.just(
                new ForumDto.Reply(42, 1, "sub-other", "old", Instant.parse("2026-06-11T00:00:00Z"))));
        when(forum.isOwnerOrAdmin(eq("sub-other"), any())).thenReturn(false);
        when(phpbb.editPost(anyLong(), any())).thenReturn(Mono.empty());
        asForum().put().uri("/bff/forum/posts/42").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"body\":\"new content\"}")
                .exchange().expectStatus().isForbidden();
        verify(phpbb, never()).editPost(anyLong(), any());
    }

    @Test
    // WRONG-OBJECT (BOLA) REGRESSION: the gate must read the POST being mutated, not a
    // same-numbered TOPIC. Here topic 42 is owned by the caller but post 42 is owned by
    // someone else; the OLD code authorized off getTopic(42) and let the edit through —
    // the fix resolves getPost(42) and DENIES. getTopic is never consulted.
    void editPost_authorizesAgainstPostNotSameIdTopic() {
        when(phpbb.isEnabled()).thenReturn(true);
        // The decoy: a topic with the SAME id 42 that the CALLER owns.
        when(phpbb.getTopic(42L)).thenReturn(Mono.just(
                new ForumDto.Topic(42, 1, "caller's topic", "sub-caller", 0, Instant.parse("2026-06-11T00:00:00Z"))));
        // The real post 42 is authored by someone else.
        when(phpbb.getPost(42L)).thenReturn(Mono.just(
                new ForumDto.Reply(42, 99, "sub-other", "victim's post", Instant.parse("2026-06-11T00:00:00Z"))));
        when(forum.isOwnerOrAdmin(eq("sub-other"), any())).thenReturn(false);
        when(forum.isOwnerOrAdmin(eq("sub-caller"), any())).thenReturn(true); // would WRONGLY pass if topic were used
        when(phpbb.editPost(anyLong(), any())).thenReturn(Mono.empty());
        asForum().put().uri("/bff/forum/posts/42").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"body\":\"hijack\"}")
                .exchange().expectStatus().isForbidden();
        verify(phpbb, never()).editPost(anyLong(), any());
        verify(phpbb, never()).getTopic(anyLong());     // the post mutation must NOT consult a topic
    }

    @Test
    // STUB-SEAM: with phpbb.enabled=false the seam can't verify ownership and there is no
    // real write — the gate returns 202 pending and mutates NOTHING (fail-closed).
    void editPost_stubSeamReturnsPending_andNeverWrites() {
        when(phpbb.isEnabled()).thenReturn(false);
        when(phpbb.editPost(anyLong(), any())).thenReturn(Mono.empty());
        asForum().put().uri("/bff/forum/posts/42").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"body\":\"new content\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.state").isEqualTo("pending");
        verify(phpbb, never()).editPost(anyLong(), any());
        verify(phpbb, never()).getPost(anyLong());
    }

    // ── create reply (ALLOW) ──────────────────────────────────────────
    @Test
    // USER-SITUATIONAL (P1-12): forum user posts a reply — ensureUser + createReply succeed, 200 returned.
    void createReply_allowedForForumUser() {
        when(forum.ensureUser(any())).thenReturn(Mono.just(new ForumDto.ForumUser("sub-1", 10L, "REGISTERED")));
        when(phpbb.createReply(anyLong(), any())).thenReturn(Mono.just(
                new ForumDto.Reply(1L, 1L, "sub-1", "my reply", Instant.parse("2026-06-11T00:00:00Z"))));
        asForum().post().uri("/bff/forum/topics/1/replies").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"body\":\"my reply\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.reply.body").isEqualTo("my reply");
    }
}
