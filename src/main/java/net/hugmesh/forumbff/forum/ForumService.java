package net.hugmesh.forumbff.forum;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.forumbff.external.BlockOutcome;
import net.hugmesh.forumbff.external.PhpbbAdminClient;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;
import net.hugmesh.forumbff.security.PrincipalDomain;
import net.hugmesh.forumbff.security.Roles;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The forum domain service — wraps phpBB per ROLE + ACTION and owns the cross-cutting
 * rules that the controllers re-check on top of the gateway/security gates (defence in
 * depth).
 *
 * <h2>Caller-role action matrix</h2>
 *
 * <pre>
 *  Action                         │ USER+FORUM │ MOD+FORUM │ ADMIN / SUPERADMIN
 *  ───────────────────────────────┼────────────┼───────────┼────────────────────
 *  ensureUser / read topics       │ yes        │ yes       │ yes
 *  createTopic / createReply      │ yes        │ yes       │ yes
 *  editPost / deletePost          │ own only   │ own only  │ any post
 *  moderateTopic (hide/lock/del)  │ no         │ yes       │ yes
 *  ban / unban (phpBB user)       │ no         │ no        │ yes
 *  listUsers / getUser (admin)    │ no         │ no        │ yes
 *  assignGroup / createCategory   │ no         │ no        │ yes
 *  auditTrail (read forum_action) │ no         │ yes*      │ yes (cross-domain for SUPERADMIN)
 * </pre>
 *
 * <p>* Mods read only their own brand's trail; SUPERADMIN reads every brand's.
 *
 * <h2>Cross-cutting responsibilities</h2>
 *
 * <ul>
 *   <li><b>Acts-as-user binding</b> — the phpBB user is bound to the immutable Casdoor
 *       {@code sub} (NOT the localpart; collision-safe). {@link #ensureUser} lazily
 *       resolves/creates it on first call and caches the binding in
 *       {@code forum_user_role}.</li>
 *   <li><b>Ownership enforcement</b> — {@link #isOwnerOrAdmin} enforces
 *       {@code post.authorSubject == jwt.sub || ROLE_ADMIN} for edit/delete (the
 *       fail-closed reactive gate in {@code ForumController.gatePost} calls this
 *       predicate directly; {@link #assertOwnerOrAdmin} is a throwing convenience
 *       wrapper around it, not currently used in production code); never accept an
 *       authorSubject from the request body.</li>
 *   <li><b>Declarative group sync</b> — {@link #computeGroup} maps the caller's CURRENT
 *       Casdoor roles to the single target {@link ForumGroup} (the extension re-derives
 *       authority from the JWT; this mapping is advisory). {@link #syncGroups(org.springframework.security.core.Authentication)}
 *       converges the extension to exactly that set (a demoted mod loses
 *       GLOBAL_MODERATORS).</li>
 *   <li><b>Ban congruence</b> — {@link #ban} / {@link #unban} call the
 *       {@link PhpbbAdminClient} stub-seam and ALWAYS audit to {@code forum_action}
 *       regardless of the (stubbed/degraded/ok) external outcome.</li>
 *   <li><b>Moderation gate</b> — {@link #assertModerator} re-checks ADMIN OR
 *       (MOD AND FORUM) at the service layer, independent of the {@code @PreAuthorize}
 *       method gate (defence in depth).</li>
 *   <li><b>Domain-scope</b> — the {@code forum_user_role} binding cache and the
 *       {@code forum_action} audit trail are per-brand. The service derives the
 *       caller's {@code domain} SERVER-SIDE from the validated-issuer brand
 *       ({@link PrincipalDomain}) and stamps/scopes those rows. A forum admin/mod of
 *       brand X never reads brand Y's data; SUPERADMIN is unscoped. This is
 *       ADDITIONAL to (never a replacement for) owner-enforcement.</li>
 * </ul>
 *
 * @see net.hugmesh.forumbff.phpbb.PhpbbApiClient
 * @see PhpbbAdminClient
 * @see ForumActionRepository
 * @see ForumUserRoleRepository
 * @see PrincipalDomain
 */
@Service
public class ForumService {

    private final PhpbbApiClient phpbb;
    private final PhpbbAdminClient phpbbAdmin;
    private final ForumUserRoleRepository userRoles;
    private final ForumActionRepository audit;
    private final PrincipalDomain principalDomain;

    public ForumService(PhpbbApiClient phpbb, PhpbbAdminClient phpbbAdmin,
                        ForumUserRoleRepository userRoles, ForumActionRepository audit,
                        PrincipalDomain principalDomain) {
        this.phpbb = phpbb;
        this.phpbbAdmin = phpbbAdmin;
        this.userRoles = userRoles;
        this.audit = audit;
        this.principalDomain = principalDomain;
    }

    /**
     * The caller's effective domain-scope, derived SERVER-SIDE from the validated JWT
     * issuer ({@link PrincipalDomain}): {@code null} for SUPERADMIN (cross-domain
     * bypass), else the concrete {@code DOMAIN_<x>} (a {@code __deny__} sentinel for a
     * non-SUPERADMIN whose issuer can't be resolved — fail-closed). When the principal
     * is not a {@link Jwt} (e.g. a test stub with a non-JWT principal) we fall back to
     * the platform {@code default} domain so single-tenant/test paths are unchanged.
     * NEVER read from a request field.
     *
     * @param auth the current caller's {@link Authentication}
     * @return the domain string to scope DB predicates on; {@code null} for SUPERADMIN
     *         bypass, {@code "__deny__"} for an unresolvable non-SUPERADMIN issuer,
     *         or a concrete {@code DOMAIN_<x>} brand string
     */
    private String scopeOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return principalDomain.forScope(jwt);
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }

    // ── Acts-as-user binding (keyed by Casdoor sub, NOT localpart) ─────

    /**
     * Lazily resolve or create the phpBB user for the caller's Casdoor subject and cache
     * the binding in {@code forum_user_role}. Two JWTs sharing the same localpart but with
     * different {@code sub} values resolve to two DISTINCT phpBB users — {@code sub} is
     * the immutable uniqueness key and is NEVER the localpart.
     *
     * <p>Reactive pipeline:
     *
     * <pre>
     *   phpbb.ensureUser(subject)        ← POST /users/{sub}/ensure (creates if absent)
     *     → flatMap: userRoles.upsert()  ← stamp binding + group in forum_user_role
     *     → switchIfEmpty: upsert()      ← extension dark: cache group with null phpbbUserId
     *       → return degraded ForumUser(subject, 0, group)
     * </pre>
     *
     * @param auth the caller's {@link Authentication} (subject + roles derived from it)
     * @return a {@code Mono} emitting the resolved or newly created
     *         {@link ForumDto.ForumUser}; emits a degraded stub (phpbbUserId=0) when
     *         the phpBB extension seam is dark
     */
    public Mono<ForumDto.ForumUser> ensureUser(Authentication auth) {
        String subject = subject(auth);
        ForumGroup group = computeGroup(auth);
        String domain = scopeOf(auth);   // server-derived brand; stamps the binding row
        return phpbb.ensureUser(subject)
                .flatMap(user -> userRoles.upsert(subject, user.phpbbUserId(), group.name(), domain).thenReturn(user))
                .switchIfEmpty(userRoles.upsert(subject, null, group.name(), domain)
                        .thenReturn(new ForumDto.ForumUser(subject, 0L, group.name())));
    }

    // ── Ownership ──────────────────────────────────────────────────────

    /**
     * Non-throwing owner-OR-admin predicate for the reactive fail-closed gate. Returns
     * {@code true} iff the caller holds ROLE_ADMIN or ROLE_SUPERADMIN, OR the caller's
     * Casdoor subject equals the resolved {@code authorSubject}. A null/blank author or
     * a null caller subject returns {@code false} (fail-closed) — the controller turns a
     * {@code false} into a 403/404 BEFORE the write is assembled.
     *
     * @param authorSubject the Casdoor {@code sub} of the resource owner (from the
     *                      post/reply returned by the extension); {@code null} fails
     *                      closed
     * @param auth          the current caller's {@link Authentication}
     * @return {@code true} iff the caller is an admin or owns the resource
     */
    public boolean isOwnerOrAdmin(String authorSubject, Authentication auth) {
        if (isAdmin(auth)) return true;
        String subject = subject(auth);
        return subject != null && subject.equals(authorSubject);
    }

    /**
     * Owner-OR-admin enforcement for edit/delete. Compares {@code authorSubject} to the
     * caller's Casdoor subject; ROLE_ADMIN (and ROLE_SUPERADMIN via the hierarchy) always
     * passes. Throws a 403 {@link ApiException} if the caller is neither the owner nor an
     * admin. Throwing convenience wrapper around {@link #isOwnerOrAdmin} for non-reactive
     * call sites; the production edit/delete path ({@code ForumController.gatePost}) calls
     * {@link #isOwnerOrAdmin} directly inside a reactive {@code filterWhen}/{@code
     * switchIfEmpty} chain instead, since throwing from within that chain isn't the idiom
     * used there.
     *
     * @param authorSubject the Casdoor {@code sub} of the resource owner
     * @param auth          the current caller's {@link Authentication}
     * @throws ApiException with HTTP 403 when the caller is not the owner and not an admin
     */
    public void assertOwnerOrAdmin(String authorSubject, Authentication auth) {
        if (!isOwnerOrAdmin(authorSubject, auth)) {
            throw ApiException.forbidden("not the owner of this post");
        }
    }

    // ── Role -> phpBB group (advisory; extension re-derives authority) ──

    /**
     * Resolves the single target {@link ForumGroup} for the caller's CURRENT Casdoor
     * roles. Delegates to {@link ForumGroup#forAuthentication(Authentication)}.
     *
     * @param auth the current caller's {@link Authentication}
     * @return the single highest {@link ForumGroup} the caller maps to; never {@code null}
     */
    public ForumGroup computeGroup(Authentication auth) {
        return ForumGroup.forAuthentication(auth);
    }

    /**
     * Declarative group sync — compute the target group from the caller's roles and push
     * the FULL target set to the phpBB extension (which converges, removing any stale
     * memberships). Carries {@code lastSynced} so the extension can resolve the
     * lazy-vs-reconcile race on concurrent sync calls.
     *
     * @param auth the current caller's {@link Authentication} (roles + subject derived
     *             from it)
     * @return a {@code Mono<Void>} that completes when the group sync and the
     *         {@code forum_user_role} upsert have both finished; empty Mono when the
     *         extension seam is dark
     */
    public Mono<Void> syncGroups(Authentication auth) {
        String subject = subject(auth);
        ForumGroup group = computeGroup(auth);
        String domain = scopeOf(auth);   // server-derived brand; stamps the binding row
        ForumDto.GroupAssignment assignment =
                new ForumDto.GroupAssignment(subject, group, roleNames(auth), Instant.now());
        return phpbb.setUserGroups(assignment)
                .then(userRoles.upsert(subject, null, group.name(), domain).then());
    }

    /**
     * Admin-initiated declarative group sync for a target {@code subject} — reconciles
     * phpBB group membership after a Casdoor role change. The target group is resolved
     * from the cached {@code forum_user_role} binding (the last computed group); falls
     * back to {@link ForumGroup#NONE} if no binding exists. The actor's domain (from
     * the admin JWT) scopes the DB row. The action is audited to {@code forum_action}
     * regardless of the external outcome (STUBBED or ok).
     *
     * @param auth    the acting admin's {@link Authentication} (domain + subject derived
     *                from it; must hold ROLE_ADMIN or ROLE_SUPERADMIN)
     * @param subject the Casdoor {@code sub} of the user whose groups are being reconciled
     * @return a {@code Mono<Void>} that completes after the extension sync and the audit
     *         record have been written; empty Mono when the extension seam is dark
     */
    public Mono<Void> syncGroups(Authentication auth, String subject) {
        String domain = scopeOf(auth);
        return userRoles.findBySubject(subject, domain)
                // resolve the last computed group from the cached binding (NONE if the column is null)
                .map(r -> ForumGroup.valueOf(r.groupMembership() != null ? r.groupMembership() : ForumGroup.NONE.name()))
                // no binding row at all => fall back to NONE (no forum group)
                .defaultIfEmpty(ForumGroup.NONE)
                // converge the extension to that single target set, then audit the sync as OK
                .flatMap(group -> {
                    ForumDto.GroupAssignment assignment =
                            new ForumDto.GroupAssignment(subject, group, List.of(group.name()), Instant.now());
                    return phpbb.setUserGroups(assignment)
                            .then(audit.record(actor(auth), ForumActionVerb.USER_SYNC_GROUPS.token(), subject,
                                    "ok", group.name(), domain))
                            .then();
                });
    }

    // ── Moderation gate (ADMIN OR (MOD AND FORUM)) ─────────────────────

    /**
     * Service-layer re-check of the moderation authority (defence in depth on top of the
     * method-level {@code @PreAuthorize}). Hierarchy-aware per the platform cascade
     * {@code SUPERADMIN ≥ ADMIN ≥ MOD ≥ USER}: ADMIN — and SUPERADMIN, which strictly
     * outranks it — pass ({@link #isAdmin} honours the cascade). Otherwise BOTH
     * {@code ROLE_MOD} AND {@code ROLE_FORUM} are required — a ROLE_MOD without ROLE_FORUM
     * and a plain USER are both denied.
     *
     * @param auth the current caller's {@link Authentication}
     * @throws ApiException with HTTP 403 when the caller is not an admin and does not
     *                      hold both ROLE_MOD and ROLE_FORUM
     */
    public void assertModerator(Authentication auth) {
        if (isAdmin(auth)) return;
        Set<String> roles = roleSet(auth);
        boolean modAndForum = roles.contains(ForumGroup.ROLE_MOD) && roles.contains(ForumGroup.ROLE_FORUM);
        if (!modAndForum) {
            throw ApiException.forbidden(
                    "forum moderation requires ROLE_SUPERADMIN/ROLE_ADMIN or (ROLE_MOD and ROLE_FORUM)");
        }
    }

    // ── Ban congruence (forum-role removal -> phpBB suspend), audited ──

    /**
     * Suspend/ban a user in phpBB — the congruence of removing the forum role — keyed by
     * the immutable Casdoor {@code sub}. Always audits to {@code forum_action} regardless
     * of the (stubbed/degraded/ok) external outcome so a stubbed ban is still
     * fully auditable.
     *
     * @param targetSubject the Casdoor {@code sub} of the user to ban
     * @param reason        a human-readable ban reason; may be {@code null}
     * @param actor         the acting admin's {@link Authentication} (subject + domain
     *                      derived from it; must hold ROLE_ADMIN or ROLE_SUPERADMIN)
     * @return a {@code Mono} emitting the {@link BlockOutcome} from the phpBB extension
     *         ({@link BlockOutcome#OK}, {@link BlockOutcome#STUBBED}, or degraded)
     */
    public Mono<BlockOutcome> ban(String targetSubject, String reason, Authentication actor) {
        String domain = scopeOf(actor);
        return phpbbAdmin.suspendUser(targetSubject, reason)
                .flatMap(outcome -> audit.record(actor(actor), ForumActionVerb.USER_BAN.token(), targetSubject,
                                outcome.result(), reason, domain)
                        .thenReturn(outcome));
    }

    /**
     * Lift a previously applied phpBB ban and re-add the user to the groups matching
     * their current roles. Audited to {@code forum_action} regardless of the external
     * outcome.
     *
     * @param targetSubject the Casdoor {@code sub} of the user to unban
     * @param reason        a human-readable reason; may be {@code null}
     * @param actor         the acting admin's {@link Authentication}
     * @return a {@code Mono} emitting the {@link BlockOutcome} from the phpBB extension
     */
    public Mono<BlockOutcome> unban(String targetSubject, String reason, Authentication actor) {
        String domain = scopeOf(actor);
        return phpbbAdmin.unsuspendUser(targetSubject, reason)
                .flatMap(outcome -> audit.record(actor(actor), ForumActionVerb.USER_UNBAN.token(), targetSubject,
                                outcome.result(), reason, domain)
                        .thenReturn(outcome));
    }

    // ── Admin console reads + writes (the /bff/forum/admin/** contract) ─

    /**
     * Lists all phpBB users (the admin-bff console memberlist). Reads through the phpBB
     * extension via {@link net.hugmesh.forumbff.phpbb.PhpbbApiClient#listUsers()},
     * which returns empty when the extension seam is dark ({@code phpbb.enabled=false})
     * so this never hard-fails. Read-only; not audited.
     *
     * @param auth the acting admin's {@link Authentication} (must hold ROLE_ADMIN or
     *             ROLE_SUPERADMIN — enforced at the controller level)
     * @return a {@code Flux} of {@link ForumDto.ForumUser} records; empty when the
     *         phpBB extension seam is dark or the memberlist is empty
     */
    public Flux<ForumDto.ForumUser> listUsers(Authentication auth) {
        return phpbb.listUsers();
    }

    /**
     * Reads one phpBB user by Casdoor {@code sub}. Returns empty when the extension seam
     * is dark ({@code phpbb.enabled=false}) or the user does not exist in phpBB.
     *
     * @param auth    the acting admin's {@link Authentication}
     * @param subject the Casdoor {@code sub} of the user to look up
     * @return a {@code Mono} emitting the {@link ForumDto.ForumUser} when found;
     *         empty when the extension seam is dark or the user is absent
     */
    public Mono<ForumDto.ForumUser> getUser(Authentication auth, String subject) {
        return phpbb.getUser(subject);
    }

    /**
     * Declaratively assigns a target user to a named phpBB group (the admin-bff console's
     * explicit {@code POST /users/{id}/groups {group}}). Distinct from the cache-derived
     * {@link #syncGroups(Authentication, String)}: here the admin explicitly names the
     * target group. The group name is validated against {@link ForumGroup} (a bad name
     * causes an {@link IllegalArgumentException} at the controller, returned as 400).
     * Pushes the full target set to the extension and audits regardless of the
     * (dark/degraded/ok) outcome.
     *
     * @param auth      the acting admin's {@link Authentication}
     * @param subject   the Casdoor {@code sub} of the user to assign
     * @param groupName a valid {@link ForumGroup} name (e.g. {@code REGISTERED},
     *                  {@code GLOBAL_MODERATORS})
     * @return a {@code Mono<Void>} that completes after the extension sync and audit
     *         record have finished; empty Mono when the extension seam is dark
     * @throws IllegalArgumentException if {@code groupName} is not a valid
     *                                  {@link ForumGroup} constant
     */
    public Mono<Void> assignGroup(Authentication auth, String subject, String groupName) {
        String domain = scopeOf(auth);
        ForumGroup group = ForumGroup.valueOf(groupName);
        ForumDto.GroupAssignment assignment =
                new ForumDto.GroupAssignment(subject, group, List.of(group.name()), Instant.now());
        return phpbb.setUserGroups(assignment)
                .then(audit.record(actor(auth), ForumActionVerb.USER_ASSIGN_GROUP.token(), subject,
                        "ok", group.name(), domain))
                .then();
    }

    /**
     * Lists all phpBB forum categories (boards). Read-through to the extension; empty
     * when the extension seam is dark.
     *
     * @param auth the acting admin's {@link Authentication}
     * @return a {@code Flux} of {@link ForumDto.Category} records; empty when the
     *         extension seam is dark
     */
    public Flux<ForumDto.Category> listCategories(Authentication auth) {
        return phpbb.listCategories();
    }

    /**
     * Creates a phpBB forum board (category). Forwarded to the extension via
     * {@link net.hugmesh.forumbff.phpbb.PhpbbApiClient#createCategory}; audited to
     * {@code forum_action} regardless of the (dark/degraded/ok) outcome. When the
     * extension seam is dark the create returns empty (no category object) but the intent
     * is still audited as {@code stubbed}.
     *
     * @param auth the acting admin's {@link Authentication}
     * @param body the validated {@link ForumDto.CreateCategory} request body
     * @return a {@code Mono} emitting the newly created {@link ForumDto.Category};
     *         empty when the extension seam is dark
     */
    public Mono<ForumDto.Category> createCategory(Authentication auth, ForumDto.CreateCategory body) {
        String domain = scopeOf(auth);
        return phpbb.createCategory(body)
                // created => audit the intent as OK and pass the new category through.
                .flatMap(cat -> audit.record(actor(auth), ForumActionVerb.CATEGORY_CREATE.token(), body.name(),
                        "ok", body.description(), domain).thenReturn(cat))
                // dark seam (extension returned empty) => still audit the intent, as STUBBED.
                .switchIfEmpty(audit.record(actor(auth), ForumActionVerb.CATEGORY_CREATE.token(), body.name(),
                        "stubbed", body.description(), domain).then(Mono.empty()));
    }

    /**
     * Returns the admin moderation queue — pending/flagged posts awaiting approve/reject.
     * Read-through to the extension; empty when the extension seam is dark.
     *
     * @param auth the acting admin's {@link Authentication}
     * @return a {@code Flux} of {@link ForumDto.QueueItem} records; empty when the
     *         extension seam is dark or the queue is empty
     */
    public Flux<ForumDto.QueueItem> moderationQueue(Authentication auth) {
        return phpbb.moderationQueue();
    }

    /**
     * Approves a queued post by id. Forwarded to the extension; audited to
     * {@code forum_action} regardless of outcome. No external effect when the extension
     * seam is dark, but the intent is still audited.
     *
     * @param auth the acting admin's {@link Authentication}
     * @param id   the queue-item identifier of the post to approve
     * @return a {@code Mono<Void>} that completes after the extension call and audit
     *         record have finished
     */
    public Mono<Void> approveQueued(Authentication auth, String id) {
        String domain = scopeOf(auth);
        return phpbb.approveQueued(id)
                .then(audit.record(actor(auth), ForumActionVerb.MODERATION_APPROVE.token(), id, "ok", null, domain))
                .then();
    }

    /**
     * Rejects a queued post by id. Forwarded to the extension; audited to
     * {@code forum_action} regardless of outcome.
     *
     * @param auth the acting admin's {@link Authentication}
     * @param id   the queue-item identifier of the post to reject
     * @return a {@code Mono<Void>} that completes after the extension call and audit
     *         record have finished
     */
    public Mono<Void> rejectQueued(Authentication auth, String id) {
        String domain = scopeOf(auth);
        return phpbb.rejectQueued(id)
                .then(audit.record(actor(auth), ForumActionVerb.MODERATION_REJECT.token(), id, "ok", null, domain))
                .then();
    }

    // ── Audit read + install-audit (domain-scoped) ─────────────────────

    // ── Audit-trail read bounds (anti-DoS) ─────────────────────────────

    /** The default newest-first cap applied to the audit trail when no {@code ?limit=}
     *  is given — bounds the {@code GET /bff/forum/admin/audit} read so an admin never
     *  collects the WHOLE forum_action table into memory by default. */
    public static final int FORUM_AUDIT_DEFAULT_LIMIT = 200;

    /** The HARD ceiling on the audit-trail read — any larger requested {@code ?limit=}
     *  is clamped DOWN to this server-side, so a caller can never widen the scan past
     *  this regardless of the request. */
    public static final int FORUM_AUDIT_MAX_LIMIT = 1000;

    /**
     * Returns the {@code forum_action} audit trail the caller may read, BOUNDED to the
     * default cap ({@link #FORUM_AUDIT_DEFAULT_LIMIT}). Scoped to the caller's brand (a
     * forum admin of brand X sees only brand X's actions); a SUPERADMIN reads every
     * brand's trail. The domain is derived server-side from the validated issuer — never
     * a request field.
     *
     * @param auth the current caller's {@link Authentication}
     * @return a {@code Flux} of at most {@link #FORUM_AUDIT_DEFAULT_LIMIT}
     *         {@link ForumAction} rows scoped to the caller's brand, ordered newest-first;
     *         SUPERADMIN callers receive all brands' rows (still capped)
     */
    public Flux<ForumAction> auditTrail(Authentication auth) {
        return auditTrail(auth, null);
    }

    /**
     * Returns the {@code forum_action} audit trail the caller may read, BOUNDED to a
     * server-clamped row cap (the anti-DoS bound on the unbounded table). The requested
     * {@code limit} is the optional {@code ?limit=} query param: a {@code null}/absent or
     * non-positive value falls back to {@link #FORUM_AUDIT_DEFAULT_LIMIT}, and any value
     * above {@link #FORUM_AUDIT_MAX_LIMIT} is clamped DOWN to that ceiling — the cap is
     * ALWAYS enforced server-side, never trusted from the request. Domain scoping is
     * unchanged (brand-scoped; SUPERADMIN cross-domain).
     *
     * @param auth  the current caller's {@link Authentication}
     * @param limit the requested cap from {@code ?limit=} (nullable); clamped to
     *              {@code [1, }{@link #FORUM_AUDIT_MAX_LIMIT}{@code ]} with a
     *              {@link #FORUM_AUDIT_DEFAULT_LIMIT} default
     * @return a {@code Flux} of at most the clamped-limit {@link ForumAction} rows scoped
     *         to the caller's brand, ordered newest-first
     */
    public Flux<ForumAction> auditTrail(Authentication auth, Integer limit) {
        return audit.list(scopeOf(auth), clampAuditLimit(limit));
    }

    /**
     * Clamps a requested audit-trail row {@code limit} into the safe range: a
     * {@code null}/absent or non-positive value yields {@link #FORUM_AUDIT_DEFAULT_LIMIT};
     * any value above {@link #FORUM_AUDIT_MAX_LIMIT} is clamped DOWN to that hard ceiling.
     *
     * @param limit the requested limit (nullable)
     * @return the clamped limit in {@code [1, }{@link #FORUM_AUDIT_MAX_LIMIT}{@code ]}
     */
    public static int clampAuditLimit(Integer limit) {
        if (limit == null || limit <= 0) {
            return FORUM_AUDIT_DEFAULT_LIMIT;
        }
        return Math.min(limit, FORUM_AUDIT_MAX_LIMIT);
    }

    /**
     * Records a style or extension install action in the actor's brand's audit trail.
     * The {@code target} is the style/extension name. The actor's server-derived domain
     * is stamped so the row lands in the correct brand's trail.
     *
     * @param actor  the acting admin's {@link Authentication}
     * @param action the action verb (e.g. {@code admin.forum.style.install},
     *               {@code admin.forum.extension.install})
     * @param name   the name of the style or extension being installed
     * @return a {@code Mono} emitting the persisted {@link ForumAction} audit row
     */
    public Mono<ForumAction> recordInstall(Authentication actor, String action, String name) {
        return audit.record(actor(actor), action, name, "ok", null, scopeOf(actor));
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /**
     * Returns the Casdoor JWT subject ({@code sub}) for the given {@link Authentication},
     * or {@code null} when {@code auth} is {@code null}.
     *
     * @param auth the caller's {@link Authentication}; may be {@code null}
     * @return the authentication name (Casdoor {@code sub}), or {@code null}
     */
    public static String subject(Authentication auth) {
        return auth == null ? null : auth.getName();
    }

    /**
     * Returns the actor name for audit rows — the Casdoor {@code sub} of the acting
     * principal, or the literal {@code "system"} when {@code auth} is {@code null}
     * (e.g. a server-initiated action).
     *
     * @param auth the acting principal's {@link Authentication}; may be {@code null}
     * @return the actor name for {@code forum_action.actor_subject}
     */
    private static String actor(Authentication auth) {
        return auth == null ? "system" : auth.getName();
    }

    /**
     * Hierarchy-aware ADMIN check — honours the platform role cascade
     * {@code SUPERADMIN ≥ ADMIN ≥ MOD ≥ USER}: a principal carrying {@code ROLE_ADMIN}
     * OR the {@code ROLE_SUPERADMIN} super-role (which strictly outranks ADMIN) is
     * "admin" here. This makes the service-layer re-checks ({@link #assertModerator},
     * {@link #isOwnerOrAdmin}) consistent with the {@code @PreAuthorize}/route gates,
     * which already let SUPERADMIN reach the ADMIN surface via the SecurityConfig role
     * hierarchy ({@code ROLE_SUPERADMIN > ROLE_ADMIN}). Without the SUPERADMIN arm a
     * SUPERADMIN — whose converted authorities are {@code ROLE_USER + ROLE_SUPERADMIN +
     * DOMAIN_x}, with NO raw {@code ROLE_ADMIN} — would pass the method gate yet be
     * denied by this defence-in-depth re-check (the inconsistency: 200 at
     * {@code /admin}, 403 at {@code /moderation}). The cascade is NOT broadened beyond
     * SUPERADMIN/ADMIN: a plain USER (or a bare MOD without FORUM) is still denied, and
     * domain-scoping is unchanged (a non-SUPERADMIN admin/mod still acts only in its own
     * brand). */
    public static boolean isAdmin(Authentication auth) {
        return roleSet(auth).contains(ForumGroup.ROLE_ADMIN) || Roles.isSuperadmin(auth);
    }

    private static Set<String> roleSet(Authentication auth) {
        if (auth == null) return Set.of();
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    private static List<String> roleNames(Authentication auth) {
        return roleSet(auth).stream().sorted().toList();
    }
}
