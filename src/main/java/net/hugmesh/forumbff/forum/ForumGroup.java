package net.hugmesh.forumbff.forum;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Casdoor role -> phpBB built-in group mapping (the role table from the design).
 * Used by {@link ForumService} to compute the DECLARATIVE target group set for the
 * extension's {@code setUserGroups} (the extension re-derives authority from the
 * verified JWT; this mapping is advisory). The set is AUTHORITATIVE — every sync
 * converges to exactly this set, so a demoted mod loses GLOBAL_MODERATORS.
 *
 * <h3>Mapping (load-bearing)</h3>
 * <ul>
 *   <li>ROLE_ADMIN -> {@link #ADMINISTRATORS} <b>ALWAYS</b>, regardless of the forum
 *       role (admins never need ROLE_FORUM);</li>
 *   <li>ROLE_MOD -> {@link #GLOBAL_MODERATORS} <b>iff</b> the user ALSO holds the forum
 *       role (ROLE_FORUM) — ROLE_MOD WITHOUT ROLE_FORUM is NOT a global moderator and
 *       has no forum access;</li>
 *   <li>forum role (ROLE_FORUM), non-admin -> {@link #REGISTERED} (post/reply);</li>
 *   <li>none of the above -> {@link #NONE} (no forum group; access denied).</li>
 * </ul>
 *
 * @see net.hugmesh.forumbff.forum.ForumService#computeGroup
 * @see net.hugmesh.forumbff.forum.ForumService#syncGroups(org.springframework.security.core.Authentication)
 */
public enum ForumGroup {

    /** ROLE_ADMIN -> phpBB ADMINISTRATORS, always. */
    ADMINISTRATORS,
    /** ROLE_MOD AND ROLE_FORUM -> phpBB GLOBAL_MODERATORS. */
    GLOBAL_MODERATORS,
    /** ROLE_FORUM (non-admin, non-mod) -> phpBB REGISTERED USERS. */
    REGISTERED,
    /** No mapping — no phpBB group; forum access denied. */
    NONE;

    public static final String ROLE_SUPERADMIN = "ROLE_SUPERADMIN";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_MOD = "ROLE_MOD";
    public static final String ROLE_FORUM = "ROLE_FORUM";

    /**
     * Resolves the single highest phpBB group from a set of Spring Security authority
     * name strings. ADMIN (or SUPERADMIN) always dominates. Then MOD-AND-FORUM maps to
     * GLOBAL_MODERATORS. Then FORUM-alone maps to REGISTERED. Otherwise NONE.
     *
     * <p>Note: {@code ROLE_SUPERADMIN} is NOT automatically expanded to {@code ROLE_ADMIN}
     * in a raw {@link Set} of authority names — that expansion only happens inside Spring
     * Security {@code @PreAuthorize} expressions wired with the role hierarchy. Both must
     * be checked explicitly here.
     *
     * @param authorities the set of Spring Security authority strings from the caller's
     *                    {@link org.springframework.security.core.Authentication}
     * @return the single highest {@link ForumGroup} the caller's roles map to;
     *         never {@code null}
     */
    public static ForumGroup forRoles(Set<String> authorities) {
        if (authorities.contains(ROLE_SUPERADMIN) || authorities.contains(ROLE_ADMIN)) {
            return ADMINISTRATORS;
        }
        boolean forum = authorities.contains(ROLE_FORUM);
        if (authorities.contains(ROLE_MOD) && forum) {
            return GLOBAL_MODERATORS;
        }
        if (forum) {
            return REGISTERED;
        }
        return NONE;
    }

    /**
     * Convenience overload: resolves the target phpBB group directly from a Spring
     * {@link Authentication}'s granted authorities. Delegates to
     * {@link #forRoles(Set)}.
     *
     * @param auth the current caller's {@link Authentication}; {@code null} returns
     *             {@link #NONE}
     * @return the single highest {@link ForumGroup} the caller's roles map to;
     *         {@link #NONE} when {@code auth} is {@code null}
     */
    public static ForumGroup forAuthentication(Authentication auth) {
        if (auth == null) return NONE;
        Set<String> names = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return forRoles(names);
    }

    /**
     * Returns {@code true} iff this group grants any forum access at all (i.e. the
     * caller should be allowed through to the phpBB extension). Only {@link #NONE}
     * grants no access.
     *
     * @return {@code true} for {@link #ADMINISTRATORS}, {@link #GLOBAL_MODERATORS},
     *         and {@link #REGISTERED}; {@code false} for {@link #NONE}
     */
    public boolean grantsAccess() {
        return this != NONE;
    }
}
