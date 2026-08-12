package net.hugmesh.forumbff.forum;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;

import java.util.Map;

/**
 * The forum MODERATION surface ({@code /bff/forum/moderation/**}). The gating is the
 * load-bearing AND-of-MOD+FORUM (NOT {@code hasAnyRole('MOD','ADMIN')}): the gateway
 * gates this path by the DERIVED composite role {@code ROLE_FORUM_MOD = ROLE_MOD ∩
 * ROLE_FORUM}, and HERE the method-level
 * {@code @PreAuthorize("hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))")}
 * re-expresses the AND (the gateway OR-of-allow table structurally cannot). A
 * ROLE_MOD WITHOUT ROLE_FORUM is NOT a moderator -> 403 (re-checked again in
 * {@link ForumService#assertModerator}). Admins always pass.
 *
 * <p>Moderation actions wrap the phpBB extension: hide/delete any post, lock threads,
 * view-all. No style/extension install here — those live ONLY under
 * {@code /bff/forum/admin/**} (ADMIN), structurally separated.
 */
@Tag(name = "ForumModeration", description = "MOD+FORUM (or ADMIN) moderation: hide/delete any post, "
        + "lock threads, view the moderation queue. AND-of-MOD+FORUM (not hasAnyRole).")
@RestController
@RequestMapping("/bff/forum/moderation")
@Validated
public class ModerationController {

    /** The AND-of-MOD+FORUM (or ADMIN) — NOT hasAnyRole('MOD','ADMIN'). */
    private static final String MOD_AND_FORUM_OR_ADMIN =
            "hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))";

    private final PhpbbApiClient phpbb;
    private final ForumService forum;

    public ModerationController(PhpbbApiClient phpbb, ForumService forum) {
        this.phpbb = phpbb;
        this.forum = forum;
    }

    @Operation(operationId = "viewForumModerationQueue", summary = "View the moderation queue (topics flagged/pending).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Moderation queue depth and source returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller is not ROLE_ADMIN and does not hold both ROLE_MOD and ROLE_FORUM", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(MOD_AND_FORUM_OR_ADMIN)
    @GetMapping("/queue")
    public Mono<Map<String, Object>> queue(Authentication auth) {
        forum.assertModerator(auth); // defence-in-depth service re-check
        return phpbb.stats().map(s -> Map.of("queueDepth", s.moderationQueueDepth(), "source", s.source()));
    }

    @Operation(operationId = "moderateForumTopic", summary = "Moderate a topic (hide/lock/delete) — any post, not just own.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Topic moderation action applied"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid action field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller is not ROLE_ADMIN and does not hold both ROLE_MOD and ROLE_FORUM", content = @Content),
            @ApiResponse(responseCode = "404", description = "Topic not found", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize(MOD_AND_FORUM_OR_ADMIN)
    @PostMapping("/topics/{id}")
    public Mono<Map<String, Object>> moderateTopic(@PathVariable long id,
                                                   @Valid @RequestBody ForumDto.ModerationAction action,
                                                   Authentication auth) {
        forum.assertModerator(auth);
        return phpbb.moderateTopic(id, action)
                .then(Mono.fromSupplier(() ->
                        Map.<String, Object>of("moderated", id, "action", action.action())));
    }
}
