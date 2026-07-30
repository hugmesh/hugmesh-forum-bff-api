package systems.hugmesh.forumbff.forum;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.forumbff.phpbb.PhpbbApiClient;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The user forum surface ({@code /bff/forum/**}) — the single browser->phpBB path's
 * authenticated tier. The ROLE_FORUM floor is enforced at the fe-gateway (route-access);
 * SecurityConfig gates the path {@code .authenticated()}; this controller re-checks
 * ROLE_FORUM (or ROLE_ADMIN) + ownership at the METHOD level (defence in depth) and
 * forwards to the phpBB {@code hugmesh/forum-api} extension via {@link PhpbbApiClient}
 * (the gated stub-seam; the caller's JWT is forwarded so phpBB acts as that user).
 *
 * <p>Wrap-per-action: forum role -> read all + create topic/reply + edit/delete OWN.
 * Ownership for edit/delete is enforced FAIL-CLOSED in {@link #gatePost}: the ACTUAL
 * {@code /posts/{id}} being mutated is resolved and the write is made structurally
 * dependent on {@link ForumService#isOwnerOrAdmin}, so a non-owner — or an empty/degraded
 * resolve — is denied BEFORE the destructive write is ever assembled.
 */
@Tag(name = "Forum", description = "Authenticated forum surface wrapping headless phpBB: categories, "
        + "topics, replies, and owner-scoped edit/delete. ROLE_FORUM (or ROLE_ADMIN).")
@RestController
@RequestMapping("/bff/forum")
@Validated
public class ForumController {

    /** ROLE_FORUM (the gateway floor) OR ROLE_ADMIN re-asserted at the method level. */
    private static final String FORUM_OR_ADMIN = "hasRole('FORUM') or hasRole('ADMIN')";

    private final PhpbbApiClient phpbb;
    private final ForumService forum;

    public ForumController(PhpbbApiClient phpbb, ForumService forum) {
        this.phpbb = phpbb;
        this.forum = forum;
    }

    @Operation(operationId = "listForumCategories", summary = "List forum categories.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Category list returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_FORUM or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @GetMapping("/categories")
    public Mono<Map<String, Object>> categories() {
        return phpbb.listCategories().collectList().map(c -> Map.of("categories", c));
    }

    @Operation(operationId = "listForumTopics", summary = "List topics in a category.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Topic list returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_FORUM or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @GetMapping("/topics")
    public Mono<Map<String, Object>> topics(@RequestParam long categoryId) {
        return phpbb.listTopics(categoryId).collectList().map(t -> Map.of("topics", t));
    }

    @Operation(operationId = "createForumTopic", summary = "Create a topic (acts as the caller's phpBB user).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Topic created"),
            @ApiResponse(responseCode = "202", description = "Pending — phpBB extension stub-seam is dark"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_FORUM or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @PostMapping("/topics")
    public Mono<ResponseEntity<Map<String, Object>>> createTopic(@Valid @RequestBody ForumDto.CreateTopic body,
                                                                 Authentication auth) {
        // Ensure the acts-as-user binding exists before authoring (lazy first-call).
        return forum.ensureUser(auth)
                .then(phpbb.createTopic(body))
                .map(topic -> ResponseEntity.ok(Map.<String, Object>of("topic", topic)))
                .defaultIfEmpty(pending("topic create pending — phpBB extension stub-seam (phpbb.enabled=false)"));
    }

    @Operation(operationId = "getForumTopic", summary = "Get a topic + its replies.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Topic and replies returned (empty maps when seam is dark)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_FORUM or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @GetMapping("/topics/{id}")
    public Mono<Map<String, Object>> topic(@PathVariable long id) {
        Mono<ForumDto.Topic> topic = phpbb.getTopic(id);
        Mono<List<ForumDto.Reply>> replies = phpbb.listReplies(id).collectList();
        return topic.zipWith(replies, (t, r) -> Map.<String, Object>of("topic", t, "replies", r))
                .defaultIfEmpty(Map.of("topic", Map.of(), "replies", List.of()));
    }

    @Operation(operationId = "replyToForumTopic", summary = "Reply to a topic (acts as the caller's phpBB user).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Reply created"),
            @ApiResponse(responseCode = "202", description = "Pending — phpBB extension stub-seam is dark"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_FORUM or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @PostMapping("/topics/{id}/replies")
    public Mono<ResponseEntity<Map<String, Object>>> reply(@PathVariable long id,
                                                           @Valid @RequestBody ForumDto.CreateReply body,
                                                           Authentication auth) {
        return forum.ensureUser(auth)
                .then(phpbb.createReply(id, body))
                .map(reply -> ResponseEntity.ok(Map.<String, Object>of("reply", reply)))
                .defaultIfEmpty(pending("reply pending — phpBB extension stub-seam (phpbb.enabled=false)"));
    }

    @Operation(operationId = "editForumPost", summary = "Edit a post (owner or ADMIN only).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Post edited"),
            @ApiResponse(responseCode = "202", description = "Pending — phpBB extension stub-seam is dark (ownership unverifiable; nothing written)"),
            @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller is not the post owner and lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Post not found or seam degraded", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @PutMapping("/posts/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> editPost(@PathVariable long id,
                                                             @Valid @RequestBody ForumDto.EditPost body,
                                                             Authentication auth) {
        // Fail-CLOSED ownership gate on the ACTUAL post (NOT a same-id topic): the write is
        // structurally DEPENDENT on a successful owner-or-admin check. An empty/degraded
        // resolve never falls through to the write — see gatePost().
        return gatePost(id, auth, () -> phpbb.editPost(id, body)
                .map(reply -> ResponseEntity.ok(Map.<String, Object>of("post", reply)))
                .defaultIfEmpty(pending("edit pending — phpBB extension stub-seam (phpbb.enabled=false)")));
    }

    @Operation(operationId = "deleteForumPost", summary = "Delete a post (owner or ADMIN only).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Post deleted"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller is not the post owner and lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Post not found or seam degraded", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(FORUM_OR_ADMIN)
    @DeleteMapping("/posts/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> deletePost(@PathVariable long id, Authentication auth) {
        // Fail-CLOSED ownership gate on the ACTUAL post (NOT a same-id topic): the delete is
        // structurally DEPENDENT on a successful owner-or-admin check (see gatePost()).
        return gatePost(id, auth, () -> phpbb.deletePost(id)
                .then(Mono.fromSupplier(() ->
                        ResponseEntity.ok(Map.<String, Object>of("deleted", id)))));
    }

    /**
     * The fail-CLOSED owner-or-admin gate for a per-post mutation. Resolves the ACTUAL
     * {@code /posts/{id}} being mutated (NOT a same-numbered topic — that was a wrong-object
     * BOLA), and makes the deferred write structurally DEPEND on a successful ownership
     * check:
     * <ol>
     *   <li>{@code getPost(id)} resolves the post whose {@code authorSubject} is the owner;</li>
     *   <li>{@code filterWhen(isOwnerOrAdmin)} drops the post for a non-owner non-admin;</li>
     *   <li>{@code switchIfEmpty(403)} turns that drop into a hard 403 — the write is never run;</li>
     *   <li>{@code flatMap(defer(write))} runs the mutation ONLY for an owner/admin post.</li>
     * </ol>
     * When the seam is STUBBED ({@code phpbb.enabled=false}) the resolve is empty BY DESIGN
     * and no real write exists, so we short-circuit to the {@code pending} 202 WITHOUT
     * mutating anything (fail-closed: ownership couldn't be verified, so nothing is written).
     * When the seam is ENABLED an empty resolve means the post is missing OR the breaker is
     * open/degraded — both become a hard 404 deny, NEVER a silent write.
     */
    private Mono<ResponseEntity<Map<String, Object>>> gatePost(
            long id, Authentication auth, Supplier<Mono<ResponseEntity<Map<String, Object>>>> write) {
        if (!phpbb.isEnabled()) {
            // Stub-seam: cannot verify ownership and no real write exists — report pending,
            // mutate nothing. (Never assemble the write on an unverified owner.)
            return Mono.just(pending("post mutation pending — phpBB extension stub-seam (phpbb.enabled=false)"));
        }
        return phpbb.getPost(id)
                .switchIfEmpty(Mono.error(ApiException.notFound("post not found")))
                .filterWhen(post -> Mono.just(forum.isOwnerOrAdmin(post.authorSubject(), auth)))
                .switchIfEmpty(Mono.error(ApiException.forbidden("not the owner of this post")))
                .flatMap(post -> Mono.defer(write));
    }

    /** 202 pending body when the phpBB extension is stub-seamed (phpbb.enabled=false). */
    private static ResponseEntity<Map<String, Object>> pending(String note) {
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(Map.of("state", "pending", "note", note));
    }
}
