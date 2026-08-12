package net.hugmesh.forumbff.forum;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of {@code forum_action.action} verbs — the WHAT each audited forum
 * admin/congruence action was. This is a fixed, CODE-OWNED vocabulary: every value is
 * emitted by this BFF itself ({@link ForumService} + {@link ForumAdminController}) as
 * the {@code action} column of a {@code forum_action} row. The verbs were previously
 * scattered as inline {@code String} literals at every {@code audit.record(...)} /
 * {@code recordInstall(...)} call-site; this enum replaces those literals with
 * typo-proof, exhaustive constants WITHOUT changing a single stored token.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String} literals</h2>
 * Each constant carries the EXACT lowercase-dotted token the system has always stored:
 * <ul>
 *   <li><b>DB</b> — the {@code forum_action.action varchar} column keeps its
 *       {@code admin.forum.*} strings. The entity ({@link ForumAction#action()}) still
 *       persists a {@code String} and the {@link ForumActionRepository} record overloads
 *       still take {@code String action}, so R2DBC reads/writes are unchanged; this enum
 *       is a CODE-SIDE lens over that string (callers pass {@link #token()}), never a
 *       column type change.</li>
 *   <li><b>JSON</b> — {@link #token()} is annotated {@link JsonValue}, so were an enum
 *       value ever serialized it emits the lowercase-dotted token (not the Java constant
 *       name); {@link #fromWire(String)} (also a {@link JsonCreator}) parses the same
 *       tokens back. The audit-read DTOs still surface {@code action} as a {@code String},
 *       so this is not on any current JSON path — but the round-trip is wire-safe by
 *       construction (pinned by {@code ForumActionVerbTest}).</li>
 * </ul>
 *
 * <p><b>Why an enum (vs. the {@code BlockOutcome} record).</b> Unlike the
 * {@code forum_action.outcome} vocabulary ({@code ok | stubbed | degraded:<reason>}),
 * whose {@code degraded:<reason>} arm carries a free-form runtime suffix and is therefore
 * an OPEN set correctly modeled as a value-object record, the action verbs are a fully
 * CLOSED, finite set with no runtime-variable parts — exactly the shape an enum captures.
 * Mirrors the hugmesh-federation-api {@code ScopeKind} exemplar. (Unlike {@code
 * ScopeKind}, these verbs are write-only — emitted into the audit row, never parsed back
 * off a wire path — and there is no DB CHECK constraint pinning them, so the round-trip
 * machinery below is for wire-safety by construction rather than an active read path.)
 */
public enum ForumActionVerb {

    /** Suspend/ban a user in phpBB (congruence of removing the forum role). */
    USER_BAN("admin.forum.user.ban"),
    /** Lift a phpBB ban (re-add groups per current roles). */
    USER_UNBAN("admin.forum.user.unban"),
    /** Reconcile a user's phpBB group membership from the cached binding. */
    USER_SYNC_GROUPS("admin.forum.user.sync-groups"),
    /** Declaratively assign a user to a NAMED phpBB group. */
    USER_ASSIGN_GROUP("admin.forum.user.assign-group"),
    /** Create a forum category (phpBB forum). */
    CATEGORY_CREATE("admin.forum.category.create"),
    /** Approve a queued (moderated) post. */
    MODERATION_APPROVE("admin.forum.moderation.approve"),
    /** Reject a queued (moderated) post. */
    MODERATION_REJECT("admin.forum.moderation.reject"),
    /** Install a phpBB style. */
    STYLE_INSTALL("admin.forum.style.install"),
    /** Install a phpBB extension. */
    EXTENSION_INSTALL("admin.forum.extension.install");

    private final String token;

    ForumActionVerb(String token) {
        this.token = token;
    }

    /** The exact lowercase-dotted wire token (the {@code forum_action.action} value). */
    @JsonValue
    public String token() {
        return token;
    }

    /**
     * Parse a wire token (an {@code admin.forum.*} string) to its {@link ForumActionVerb},
     * or {@code null} when the token is null / unrecognised. Null-tolerant by design,
     * mirroring the {@code ScopeKind.fromWire} exemplar — the audit trail can carry rows
     * written by an older/other code path, so an unknown verb must never throw.
     */
    @JsonCreator
    public static ForumActionVerb fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (ForumActionVerb v : values()) {
            if (v.token.equals(wire)) {
                return v;
            }
        }
        return null;
    }
}
