package net.hugmesh.forumbff.phpbb;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.forum.ForumDto;

import java.util.List;
import java.util.function.Supplier;

/**
 * Reactive client of the phpBB headless surface — the {@code hugmesh/forum-api}
 * extension at {@code /api/v1/hugmesh/**}.
 *
 * <h3>Headless mechanism (the design choice — phpBB has NO native REST API)</h3>
 * phpBB ships no first-class/official REST API. The design-chosen mechanism is a thin
 * CUSTOM phpBB extension, {@code hugmesh/forum-api}: phpBB 3.1+ runs on Symfony
 * HttpKernel, so the extension registers routes in {@code config/routing.yml},
 * returns Symfony {@code JsonResponse}, and injects phpBB's OWN services via the DI
 * container — reads AND writes go through phpBB's consistency/permission logic,
 * version-locked to the install, with no raw-DB coupling. (Candidates weighed +
 * rejected: the unofficial community REST extension [alpha, cookie-auth], phpbbcli
 * [stateful, no HTTP boundary], and direct R2DBC to the phpBB schema [bypasses phpBB
 * permission/ban checks] — see the README.)
 *
 * <h3>GATED-REAL seam — flag-gated, fail-soft (mirrors mod-bff MastodonAdminClient)</h3>
 * {@code phpbb.enabled} (default FALSE) gates the read/write seam. When OFF — and at
 * any resilience4j breaker-open / error — every method returns a TYPED degraded/empty
 * result, NEVER hard-failing the request, so forum-bff boots clean without the
 * extension. When ON, each method makes the REAL HTTP call to the
 * {@code hugmesh/forum-api} extension at {@code /api/v1/hugmesh/**}. Each call is
 * wrapped in {@code @CircuitBreaker(name="phpbb")} with a typed fallback, exactly like
 * the mod-bff homeserver clients. The caller forwards the user's Casdoor JWT
 * (Bearer + {@code X-HugMesh-JWT}) via {@link PhpbbWebClientConfig}; the extension
 * validates it against the Casdoor JWKS and re-derives authority — this client NEVER
 * sends caller-supplied group data as trusted authority.
 *
 * <p>Flipping ON is CONFIG-ONLY ({@code phpbb.enabled=true}) once the extension is
 * pinned/validated on-cluster.
 */
public class PhpbbApiClient {

    private static final Logger log = LoggerFactory.getLogger(PhpbbApiClient.class);

    private static final String BASE = "/api/v1/hugmesh";

    private final WebClient http;
    private final boolean enabled;

    public PhpbbApiClient(WebClient http, boolean enabled) {
        this.http = http;
        this.enabled = enabled;
    }

    public boolean isEnabled() { return enabled; }

    // ── Reads ──────────────────────────────────────────────────────────

    @CircuitBreaker(name = "phpbb", fallbackMethod = "categoriesFallback")
    public Flux<ForumDto.Category> listCategories() {
        if (!enabled) return Flux.empty();
        return http.get().uri(BASE + "/categories").retrieve().bodyToFlux(ForumDto.Category.class);
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "topicsFallback")
    public Flux<ForumDto.Topic> listTopics(long categoryId) {
        if (!enabled) return Flux.empty();
        return http.get().uri(uri -> uri.path(BASE + "/topics").queryParam("categoryId", categoryId).build())
                .retrieve().bodyToFlux(ForumDto.Topic.class);
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "topicFallback")
    public Mono<ForumDto.Topic> getTopic(long topicId) {
        if (!enabled) return Mono.empty();
        return http.get().uri(BASE + "/topics/{id}", topicId).retrieve().bodyToMono(ForumDto.Topic.class);
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "repliesFallback")
    public Flux<ForumDto.Reply> listReplies(long topicId) {
        if (!enabled) return Flux.empty();
        return http.get().uri(BASE + "/topics/{id}/replies", topicId).retrieve().bodyToFlux(ForumDto.Reply.class);
    }

    /**
     * Resolve a single POST (phpBB post) by its id for OWNERSHIP enforcement on
     * edit/delete — the {@code authorSubject} on the returned {@link ForumDto.Reply} is
     * the post owner's Casdoor sub. Hits {@code /api/v1/hugmesh/posts/{id}} (the post,
     * NOT the same-numbered topic). When the seam is stubbed/degraded it returns empty;
     * the caller MUST treat that empty as deny (fail-closed), never as "owner verified".
     */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "getPostFallback")
    public Mono<ForumDto.Reply> getPost(long postId) {
        if (!enabled) return Mono.empty();
        return http.get().uri(BASE + "/posts/{id}", postId).retrieve().bodyToMono(ForumDto.Reply.class);
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "statsFallback")
    public Mono<ForumDto.Stats> stats() {
        if (!enabled) return Mono.just(ForumDto.Stats.degraded());
        return http.get().uri(BASE + "/stats").retrieve().bodyToMono(ForumDto.Stats.class);
    }

    // ── Writes (acts-as-user — author recorded under the caller's phpBB user) ──

    @CircuitBreaker(name = "phpbb", fallbackMethod = "topicFallback")
    public Mono<ForumDto.Topic> createTopic(ForumDto.CreateTopic body) {
        return call("create-topic", () ->
                http.post().uri(BASE + "/topics").bodyValue(body).retrieve().bodyToMono(ForumDto.Topic.class));
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "replyFallback")
    public Mono<ForumDto.Reply> createReply(long topicId, ForumDto.CreateReply body) {
        return call("create-reply", () ->
                http.post().uri(BASE + "/topics/{id}/replies", topicId).bodyValue(body)
                        .retrieve().bodyToMono(ForumDto.Reply.class));
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "replyFallback")
    public Mono<ForumDto.Reply> editPost(long postId, ForumDto.EditPost body) {
        return call("edit-post", () ->
                http.put().uri(BASE + "/posts/{id}", postId).bodyValue(body)
                        .retrieve().bodyToMono(ForumDto.Reply.class));
    }

    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> deletePost(long postId) {
        return call("delete-post", () ->
                http.delete().uri(BASE + "/posts/{id}", postId).retrieve().bodyToMono(Void.class));
    }

    /** Moderation: hide/lock/delete a topic/post (MOD+FORUM or ADMIN at the controller). */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> moderateTopic(long topicId, ForumDto.ModerationAction action) {
        return call("moderate-topic", () ->
                http.post().uri(BASE + "/moderation/topics/{id}", topicId).bodyValue(action)
                        .retrieve().bodyToMono(Void.class));
    }

    // ── Admin/declarative ops (ADMIN-scoped at the controller; extension re-checks) ──

    /** Lazy first-call resolve/create of the phpBB user, keyed by Casdoor sub. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "forumUserFallback")
    public Mono<ForumDto.ForumUser> ensureUser(String casdoorSubject) {
        return call("ensure-user", () ->
                http.post().uri(BASE + "/users/{sub}/ensure", casdoorSubject)
                        .retrieve().bodyToMono(ForumDto.ForumUser.class));
    }

    /** DECLARATIVE group sync — the extension converges to exactly this set (removes stale). */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> setUserGroups(ForumDto.GroupAssignment assignment) {
        return call("set-user-groups", () ->
                http.put().uri(BASE + "/users/{sub}/groups", assignment.casdoorSubject())
                        .bodyValue(assignment).retrieve().bodyToMono(Void.class));
    }

    /** Style install (ADMIN ONLY at the controller; extension re-derives ROLE_ADMIN). */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> installStyle(String name) {
        return call("install-style", () ->
                http.post().uri(BASE + "/admin/styles").bodyValue(List.of(name)).retrieve().bodyToMono(Void.class));
    }

    /** Extension install (ADMIN ONLY at the controller). */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> installExtension(String name) {
        return call("install-extension", () ->
                http.post().uri(BASE + "/admin/extensions").bodyValue(List.of(name)).retrieve().bodyToMono(Void.class));
    }

    // ── Admin-console reads/writes the admin-bff ForumAdminController proxies ──
    // These back the /bff/forum/admin/** contract admin-bff's PhpbbAdminClient calls.
    // The phpBB HTTP leg stays DARK behind the existing phpbb.enabled gate (call()):
    // every method below returns an empty/degraded result when phpbb.enabled=false, so the
    // BFF-to-BFF seam is real + testable while the extension's shape is confirmed/pinned
    // (see the README) but the flag stays off by default.

    /** ADMIN: list the phpBB users (memberlist). Empty when the extension seam is dark. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "forumUsersFallback")
    public Flux<ForumDto.ForumUser> listUsers() {
        if (!enabled) return Flux.empty();
        return http.get().uri(BASE + "/admin/users").retrieve().bodyToFlux(ForumDto.ForumUser.class);
    }

    /** ADMIN: read one phpBB user by Casdoor sub. Empty when the extension seam is dark. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "forumUserFallback")
    public Mono<ForumDto.ForumUser> getUser(String casdoorSubject) {
        if (!enabled) return Mono.empty();
        return http.get().uri(BASE + "/admin/users/{sub}", casdoorSubject)
                .retrieve().bodyToMono(ForumDto.ForumUser.class);
    }

    /** ADMIN: create a forum category (phpBB forum). Empty when the extension seam is dark. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "categoryFallback")
    public Mono<ForumDto.Category> createCategory(ForumDto.CreateCategory body) {
        return call("create-category", () ->
                http.post().uri(BASE + "/admin/categories").bodyValue(body)
                        .retrieve().bodyToMono(ForumDto.Category.class));
    }

    /** ADMIN: the moderation queue (pending/flagged posts). Empty when the seam is dark. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "queueFallback")
    public Flux<ForumDto.QueueItem> moderationQueue() {
        if (!enabled) return Flux.empty();
        return http.get().uri(BASE + "/admin/moderation-queue").retrieve().bodyToFlux(ForumDto.QueueItem.class);
    }

    /** ADMIN: approve a queued post (id). No effect when the seam is dark. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> approveQueued(String id) {
        return call("moderation-approve", () ->
                http.post().uri(BASE + "/admin/moderation/{id}/approve", id).retrieve().bodyToMono(Void.class));
    }

    /** ADMIN: reject a queued post (id). No effect when the seam is dark. */
    @CircuitBreaker(name = "phpbb", fallbackMethod = "voidFallback")
    public Mono<Void> rejectQueued(String id) {
        return call("moderation-reject", () ->
                http.post().uri(BASE + "/admin/moderation/{id}/reject", id).retrieve().bodyToMono(Void.class));
    }

    // ── The single external-call seam ──────────────────────────────────

    /**
     * GATED-REAL by {@code phpbb.enabled}: when OFF a WRITE returns an empty Mono
     * (no effect) after logging the intended action — NEVER hard-failing. When ON it
     * invokes the supplied {@code real} call against {@code hugmesh/forum-api}.
     * Flipping ON is CONFIG-ONLY ({@code phpbb.enabled=true}) once the extension is
     * validated on-cluster.
     */
    private <T> Mono<T> call(String op, Supplier<Mono<T>> real) {
        if (!enabled) {
            log.info("[phpbb] {} is INERT (phpbb.enabled=false) — no extension call made", op);
            return Mono.empty();
        }
        return real.get();
    }

    // ── Typed fallbacks (breaker-open / error — degraded, never throw) ──

    @SuppressWarnings("unused")
    private Flux<ForumDto.Category> categoriesFallback(Throwable t) { return degradedFlux("categories", t); }
    @SuppressWarnings("unused")
    private Flux<ForumDto.Topic> topicsFallback(long categoryId, Throwable t) { return degradedFlux("topics", t); }
    @SuppressWarnings("unused")
    private Flux<ForumDto.Reply> repliesFallback(long topicId, Throwable t) { return degradedFlux("replies", t); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.Topic> topicFallback(ForumDto.CreateTopic b, Throwable t) { return degradedMono("create-topic", t); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.Topic> topicFallback(long id, Throwable t) { return degradedMono("topic", t); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.Reply> replyFallback(long id, Object b, Throwable t) { return degradedMono("reply", t); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.Reply> getPostFallback(long id, Throwable t) { return degradedMono("get-post", t); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.ForumUser> forumUserFallback(String sub, Throwable t) { return degradedMono("ensure-user", t); }
    @SuppressWarnings("unused")
    private Flux<ForumDto.ForumUser> forumUsersFallback(Throwable t) { return degradedFlux("admin-users", t); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.Category> categoryFallback(ForumDto.CreateCategory b, Throwable t) { return degradedMono("create-category", t); }
    @SuppressWarnings("unused")
    private Flux<ForumDto.QueueItem> queueFallback(Throwable t) { return degradedFlux("moderation-queue", t); }
    @SuppressWarnings("unused")
    private Mono<Void> voidFallback(Object a, Throwable t) { log.warn("[phpbb] degraded: {}", t.toString()); return Mono.empty(); }
    @SuppressWarnings("unused")
    private Mono<Void> voidFallback(Object a, Object b, Throwable t) { log.warn("[phpbb] degraded: {}", t.toString()); return Mono.empty(); }
    @SuppressWarnings("unused")
    private Mono<ForumDto.Stats> statsFallback(Throwable t) {
        log.warn("[phpbb] stats degraded (breaker/err): {}", t.toString());
        return Mono.just(ForumDto.Stats.degraded());
    }

    private <T> Flux<T> degradedFlux(String op, Throwable t) {
        log.warn("[phpbb] {} degraded (breaker/err): {}", op, t.toString());
        return Flux.empty();
    }

    private <T> Mono<T> degradedMono(String op, Throwable t) {
        log.warn("[phpbb] {} degraded (breaker/err): {}", op, t.toString());
        return Mono.empty();
    }
}
