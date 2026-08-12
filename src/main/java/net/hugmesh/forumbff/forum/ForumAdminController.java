package net.hugmesh.forumbff.forum;

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
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.external.BlockOutcome;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The ADMIN-only console seam ({@code /bff/forum/admin/**}) that admin-bff's
 * {@code ForumAdminClient} calls (admin-bff -> forum-bff, which owns the single
 * {@link PhpbbApiClient} / {@code PhpbbAdminClient}). Gated {@code hasRole('ADMIN')}
 * end-to-end: SecurityConfig gates the path ADMIN, every method re-asserts
 * {@code @PreAuthorize("hasRole('ADMIN')")}, and the phpBB extension independently
 * re-derives ROLE_ADMIN from the verified JWT (triple defence). An admin reaches this
 * WITHOUT ROLE_FORUM (the converter gives admins neither ROLE_FORUM nor a superset), so
 * the path is ADMIN end-to-end and never blocked by the user floor.
 *
 * <p>Surface: ban/unban (reversible congruence), declarative group assign, live stats,
 * the {@code forum_action} audit trail, and ADMIN-ONLY style/extension install (kept
 * structurally separate from the user+mod surfaces). Every write is audited to
 * {@code forum_action} regardless of the (stubbed/degraded/ok) external outcome.
 */
@Tag(name = "ForumAdmin", description = "ADMIN-only forum console seam (admin-bff calls this): "
        + "ban/unban, group assign, stats, audit, style/extension install.")
@RestController
@RequestMapping("/bff/forum/admin")
@Validated
public class ForumAdminController {

    private final PhpbbApiClient phpbb;
    private final ForumService forum;

    public ForumAdminController(PhpbbApiClient phpbb, ForumService forum) {
        this.phpbb = phpbb;
        this.forum = forum;
    }

    @Operation(operationId = "getForumAdminStats", summary = "Live forum content stats (topics/posts/active/queue) from the extension.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Stats returned (may be empty/zero when the phpBB seam is dark)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/stats")
    public Mono<ForumDto.Stats> stats() {
        return phpbb.stats();
    }

    /**
     * Ban a user from the forum (the congruence of forum-role removal): phpBB suspend +
     * group strip + session purge, keyed by Casdoor {@code sub}. Returns
     * {@code 202 pending-reconcile} for a stubbed/degraded outcome (never a 200), always
     * audited to {@code forum_action}.
     */
    @Operation(operationId = "banForumUser", summary = "Ban a user in phpBB (congruence; STUBBED → 202 pending, always audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Ban applied in phpBB (real OK from extension)"),
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — phpBB seam is STUBBED/degraded; action audited"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/{subject}/ban")
    public Mono<ResponseEntity<Map<String, Object>>> ban(@PathVariable String subject,
                                                         @RequestParam(required = false) String reason,
                                                         @Valid @RequestBody(required = false) ForumDto.BanBody body,
                                                         Authentication auth) {
        // admin-bff's PhpbbAdminClient sends {reason} as a JSON body; the legacy ?reason=
        // query param still works (body wins when present).
        String r = body != null && body.reason() != null ? body.reason() : reason;
        return forum.ban(subject, r, auth).map(o -> outcomeResponse("ban", subject, o));
    }

    @Operation(operationId = "unbanForumUser", summary = "Lift a phpBB ban (reversible; STUBBED → 202 pending, always audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Ban lifted in phpBB (real OK from extension)"),
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — phpBB seam is STUBBED/degraded; action audited"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{subject}/ban")
    public Mono<ResponseEntity<Map<String, Object>>> unban(@PathVariable String subject,
                                                           @RequestParam(required = false) String reason,
                                                           Authentication auth) {
        return forum.unban(subject, reason, auth).map(o -> outcomeResponse("unban", subject, o));
    }

    @Operation(operationId = "installForumStyle", summary = "Install a phpBB style (ADMIN ONLY).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Style installed"),
            @ApiResponse(responseCode = "400", description = "Name missing or invalid", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/styles")
    public Mono<ResponseEntity<Map<String, Object>>> installStyle(
            @RequestParam(required = false) String name,
            @Valid @RequestBody(required = false) ForumDto.InstallBody body,
            Authentication auth) {
        String n = resolveName(name, body);
        return phpbb.installStyle(n)
                .then(forum.recordInstall(auth, ForumActionVerb.STYLE_INSTALL.token(), n))
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of("style", n, "state", "installed")));
    }

    @Operation(operationId = "installForumExtension", summary = "Install a phpBB extension (ADMIN ONLY).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Extension installed"),
            @ApiResponse(responseCode = "400", description = "Name missing or invalid", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/extensions")
    public Mono<ResponseEntity<Map<String, Object>>> installExtension(
            @RequestParam(required = false) String name,
            @Valid @RequestBody(required = false) ForumDto.InstallBody body,
            Authentication auth) {
        String n = resolveName(name, body);
        return phpbb.installExtension(n)
                .then(forum.recordInstall(auth, ForumActionVerb.EXTENSION_INSTALL.token(), n))
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of("extension", n, "state", "installed")));
    }

    // ── User console reads (the admin-bff PhpbbAdminClient memberlist) ──

    @Operation(operationId = "listForumUsers", summary = "List forum users (ADMIN; read-through phpBB; empty when seam dark).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User list returned (empty when phpBB seam is dark)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public Mono<Map<String, Object>> users(Authentication auth) {
        return forum.listUsers(auth).collectList().map(u -> Map.of("users", u));
    }

    @Operation(operationId = "getForumUser", summary = "Read one forum user by Casdoor sub (ADMIN; empty when seam dark).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Forum user returned"),
            @ApiResponse(responseCode = "204", description = "User not found in phpBB (seam dark or user absent)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users/{subject}")
    public Mono<ResponseEntity<ForumDto.ForumUser>> user(@PathVariable String subject, Authentication auth) {
        return forum.getUser(auth, subject)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.noContent().build());
    }

    /**
     * Admin-named declarative group assignment (the admin-bff console's explicit
     * {@code POST /users/{subject}/groups {group}} — distinct from the cache-derived
     * {@code PUT}). The group name is validated against {@link ForumGroup}; an unknown
     * name is a 400 (translated by {@link #invalidGroup}). Audited regardless of outcome.
     */
    @Operation(operationId = "assignForumUserGroup", summary = "Assign a target user to a NAMED phpBB group (ADMIN ONLY; audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Group assigned"),
            @ApiResponse(responseCode = "400", description = "Unknown ForumGroup name", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/{subject}/groups")
    public Mono<ResponseEntity<Void>> assignGroup(@PathVariable String subject,
                                                  @Valid @RequestBody ForumDto.GroupBody body,
                                                  Authentication auth) {
        return forum.assignGroup(auth, subject, body.group())
                .thenReturn(ResponseEntity.ok().<Void>build());
    }

    // ── Category CRUD ───────────────────────────────────────────────────

    @Operation(operationId = "listForumAdminCategories", summary = "List forum categories (ADMIN; read-through phpBB; empty when seam dark).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Category list returned (empty when phpBB seam is dark)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/categories")
    public Mono<Map<String, Object>> categories(Authentication auth) {
        return forum.listCategories(auth).collectList().map(c -> Map.of("categories", c));
    }

    @Operation(operationId = "createForumCategory", summary = "Create a forum category (ADMIN ONLY; audited). 202 when the seam is dark.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Category created in phpBB"),
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — phpBB seam is dark; action audited"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/categories")
    public Mono<ResponseEntity<Map<String, Object>>> createCategory(
            @Valid @RequestBody ForumDto.CreateCategory body, Authentication auth) {
        return forum.createCategory(auth, body)
                .map(c -> ResponseEntity.ok(Map.<String, Object>of(
                        "state", "created", "id", c.id(), "name", c.name())))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.<String, Object>of(
                        "state", "pending-reconcile", "name", body.name(),
                        "note", "phpBB extension seam is dark (phpbb.enabled=false) — "
                                + "recorded in forum_action; the reconcile job applies the real effect")));
    }

    // ── Moderation queue (approve / reject) ─────────────────────────────

    @Operation(operationId = "listForumAdminModerationQueue", summary = "List the moderation queue (ADMIN; read-through phpBB; empty when seam dark).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Moderation queue returned (empty when phpBB seam is dark)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/moderation-queue")
    public Mono<Map<String, Object>> moderationQueue(Authentication auth) {
        return forum.moderationQueue(auth).collectList().map(q -> Map.of("queue", q));
    }

    @Operation(operationId = "approveForumQueuedPost", summary = "Approve a queued post (ADMIN ONLY; audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Post approved"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Queued post not found", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/moderation/{id}/approve")
    public Mono<ResponseEntity<Map<String, Object>>> approve(@PathVariable String id, Authentication auth) {
        return forum.approveQueued(auth, id)
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of("moderated", id, "action", "approve")));
    }

    @Operation(operationId = "rejectForumQueuedPost", summary = "Reject a queued post (ADMIN ONLY; audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Post rejected"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Queued post not found", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/moderation/{id}/reject")
    public Mono<ResponseEntity<Map<String, Object>>> reject(@PathVariable String id, Authentication auth) {
        return forum.rejectQueued(auth, id)
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of("moderated", id, "action", "reject")));
    }

    /** Prefer the JSON {@code {name}} body (admin-bff console) over the legacy {@code ?name=}. */
    private static String resolveName(String name, ForumDto.InstallBody body) {
        if (body != null && body.name() != null && !body.name().isBlank()) {
            return body.name();
        }
        if (name == null || name.isBlank()) {
            throw new ServerWebInputException("name is required");
        }
        return name;
    }

    /** An unknown {@link ForumGroup} name in the assign-group body is a 400, not a 500. */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> invalidGroup(IllegalArgumentException e) {
        return Map.of("error", "invalid group", "detail", String.valueOf(e.getMessage()));
    }

    /**
     * Admin-initiated declarative group sync for a target user (identified by Casdoor
     * {@code subject}). Resolves the target's cached phpBB group from
     * {@code forum_user_role} and converges the phpBB extension to that set, audited to
     * {@code forum_action}. Used by admin-bff after a Casdoor role change to reconcile
     * phpBB group membership.
     */
    @Operation(operationId = "syncForumUserGroups", summary = "Sync phpBB group membership for a target user (ADMIN ONLY; audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Group membership synced"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Target user not found", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PutMapping("/users/{subject}/groups")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<Void>> syncGroups(
            @PathVariable String subject,
            Authentication auth) {
        ResponseEntity<Void> ok = ResponseEntity.ok().build();
        return forum.syncGroups(auth, subject).thenReturn(ok);
    }

    /**
     * Reads the {@code forum_action} audit trail, BOUNDED newest-first. The optional
     * {@code ?limit=} caps the rows; it is clamped SERVER-SIDE to
     * {@code [1, }{@value ForumService#FORUM_AUDIT_MAX_LIMIT}{@code ]} with a
     * {@value ForumService#FORUM_AUDIT_DEFAULT_LIMIT} default (an absent / non-positive /
     * over-cap value is normalised in {@link ForumService#clampAuditLimit}), so the whole
     * table can never be collected into memory (an unbounded-table DoS). ADMIN-gated and
     * domain-scoped (SUPERADMIN sees all) as before.
     */
    @Operation(operationId = "getForumAuditTrail",
            summary = "Read the forum_action audit trail (newest-first, server-capped; scoped to the caller's brand; SUPERADMIN sees all).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Audit trail returned (newest-first, server-capped; domain-scoped; SUPERADMIN sees all)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/audit")
    public Mono<Map<String, Object>> auditTrail(@RequestParam(required = false) Integer limit, Authentication auth) {
        return forum.auditTrail(auth, limit).collectList().map(a -> Map.of("actions", a));
    }

    /**
     * OUTCOME CONTRACT: a STUBBED / degraded external congruence call did NOT land the
     * phpBB effect, so return 202 pending-reconcile — only a real OK is a 200. The
     * action is audited by the service regardless.
     */
    private static ResponseEntity<Map<String, Object>> outcomeResponse(String op, String subject, BlockOutcome o) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("state", o.isOk() ? "applied" : "pending-reconcile");
        out.put("op", op);
        out.put("subject", subject);
        out.put("external", o.result());
        if (o.isStubbed()) {
            out.put("note", "phpBB extension admin call is STUBBED (external.forum.enabled=false) — "
                    + "recorded in forum_action; the reconcile job applies the real effect");
        }
        return o.isOk()
                ? ResponseEntity.ok(out)
                : ResponseEntity.status(HttpStatus.ACCEPTED).body(out);
    }
}
