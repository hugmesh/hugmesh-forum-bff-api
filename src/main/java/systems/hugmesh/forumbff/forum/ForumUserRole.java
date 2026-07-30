package systems.hugmesh.forumbff.forum;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of the {@code forum_user_role} cache (Liquibase {@code 001}). Binds the
 * phpBB user to the Casdoor {@code sub} (the IMMUTABLE uniqueness key — NOT localpart:
 * two identity providers can yield the same localpart, so {@code sub} is the only
 * collision-safe key). Carries the last computed group membership + a {@code lastSynced}
 * timestamp so the declarative {@code setUserGroups} can resolve the lazy-vs-reconcile
 * race (last-writer-by-Casdoor-time wins).
 *
 * <p>The {@code domain} (Liquibase {@code 003}) is the brand/tenant the binding
 * belongs to, stamped SERVER-SIDE from the subject's validated-issuer brand. A forum
 * admin/mod of brand X resolves only brand X's bindings; SUPERADMIN resolves any
 * brand's. (The {@code casdoor_subject} PK stays globally-unique — the Casdoor sub is
 * already collision-safe; domain is an ADDITIONAL read predicate, never the key.)
 *
 * @param casdoorSubject  the immutable Casdoor {@code sub} — PRIMARY KEY / UNIQUE
 * @param phpbbUserId     the resolved phpBB user id
 * @param groupMembership the last computed {@link ForumGroup} name
 * @param lastSynced      the timestamp of the last group write
 * @param domain          the brand/tenant the binding belongs to (server-derived; {@code default} single-tenant)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Table("forum_user_role")
public record ForumUserRole(
        @Id @Column("casdoor_subject") String casdoorSubject,
        @Column("phpbb_user_id") Long phpbbUserId,
        @Column("group_membership") String groupMembership,
        @Column("last_synced") Instant lastSynced,
        @Column("domain") String domain) {
}
