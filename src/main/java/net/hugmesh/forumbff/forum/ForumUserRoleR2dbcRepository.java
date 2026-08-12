package net.hugmesh.forumbff.forum;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for the {@code forum_user_role} binding cache
 * (Liquibase {@code 001} + {@code 003}), keyed by the IMMUTABLE Casdoor {@code sub}
 * (the PK). Mirrors the hugmesh-federation-api {@code R2dbcRepository} idiom:
 * DERIVED finders for the reads, and a {@code @Query} static-final constant only for
 * the portable insert-then-update upsert that no derived method can express (a
 * multi-column SET + {@code now()}).
 *
 * <p>The {@link ForumUserRoleRepository} facade keeps the prior public method shape
 * (back-compat overloads + the {@code null}-domain SUPERADMIN bypass); this interface
 * is the data-access layer it delegates to.
 */
public interface ForumUserRoleR2dbcRepository extends ReactiveCrudRepository<ForumUserRole, String> {

    /** SUPERADMIN cross-domain bypass read: the single binding for a Casdoor subject in
     *  ANY brand (the {@code casdoor_subject} PK is globally-unique). Equivalent to the
     *  original {@code SELECT ... WHERE casdoor_subject = :sub} (no domain predicate). */
    Mono<ForumUserRole> findByCasdoorSubject(String casdoorSubject);

    /** Domain-scoped read: the binding for a Casdoor subject WITHIN one brand.
     *  Equivalent to {@code SELECT ... WHERE casdoor_subject = :sub AND domain = :domain}. */
    Mono<ForumUserRole> findByCasdoorSubjectAndDomain(String casdoorSubject, String domain);

    /**
     * Portable upsert UPDATE leg — set the binding/group/domain and bump
     * {@code last_synced} to {@code now()} for an existing subject. Returns the number
     * of rows touched so the facade can INSERT only on a miss (keeps the SQL
     * engine-clean — no ON CONFLICT / MERGE divergence between Postgres and H2). This
     * is a multi-column SET with a DB {@code now()} call, which no derived method can
     * express, so it is a {@code @Query} bound to a static-final constant.
     */
    @Modifying
    @Query(UPDATE_BINDING)
    Mono<Long> updateBinding(@Param("sub") String casdoorSubject,
                             @Param("uid") Long phpbbUserId,
                             @Param("grp") String groupMembership,
                             @Param("dom") String domain);

    /** Portable upsert INSERT leg — insert a new binding, stamping {@code last_synced}
     *  to {@code now()}. Run only when {@link #updateBinding} touched no row. */
    @Modifying
    @Query(INSERT_BINDING)
    Mono<Long> insertBinding(@Param("sub") String casdoorSubject,
                             @Param("uid") Long phpbbUserId,
                             @Param("grp") String groupMembership,
                             @Param("dom") String domain);

    /** The UPDATE leg of the portable insert-then-update upsert (Postgres + H2). */
    String UPDATE_BINDING =
            "UPDATE forum_user_role SET phpbb_user_id = :uid, group_membership = :grp, "
                    + "domain = :dom, last_synced = now() WHERE casdoor_subject = :sub";

    /** The INSERT leg of the portable insert-then-update upsert (Postgres + H2). */
    String INSERT_BINDING =
            "INSERT INTO forum_user_role (casdoor_subject, phpbb_user_id, group_membership, domain, last_synced) "
                    + "VALUES (:sub, :uid, :grp, :dom, now())";
}
