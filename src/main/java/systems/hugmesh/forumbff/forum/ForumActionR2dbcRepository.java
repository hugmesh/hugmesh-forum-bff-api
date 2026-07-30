package systems.hugmesh.forumbff.forum;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for the {@code forum_action} audit trail
 * (Liquibase {@code 002} + {@code 003}), id app-generated (UUID String PK). Mirrors
 * the hugmesh-federation-api {@code R2dbcRepository} idiom: DERIVED, ordering-exact
 * finders for the list reads, and a {@code @Query} static-final constant only for the
 * portable INSERT that stamps {@code created_at = now()} (no derived method can express
 * a {@code now()} insert that returns nothing).
 *
 * <p>The {@link ForumActionRepository} facade keeps the prior public method shape
 * (back-compat overloads + the {@code null}-domain SUPERADMIN bypass + the read-back);
 * this interface is the data-access layer it delegates to.
 *
 * <p>DB-GENERATED UUID PK (the org-wide migration, mod-bff #36 / admin-bff #133): the
 * {@code id} is NO LONGER minted in Java. The {@code forum_action.id} column carries a
 * {@code DEFAULT (gen_random_uuid())::text} (pgcrypto, changelog 004), so the INSERT
 * OMITS {@code id} and appends {@code RETURNING id} to read the database-generated
 * 36-char UUID string back. The INSERT is therefore a plain {@code @Query} (NOT
 * {@code @Modifying}) returning {@code Mono<String>} — the generated id the facade then
 * reads the persisted row back by.
 */
public interface ForumActionR2dbcRepository extends ReactiveCrudRepository<ForumAction, String> {

    /** SUPERADMIN cross-domain bypass: the whole audit trail, newest first
     *  ({@code ORDER BY created_at DESC, id}). Equivalent to the original
     *  {@code SELECT ... FROM forum_action ORDER BY created_at DESC, id}. */
    Flux<ForumAction> findAllByOrderByCreatedAtDescIdAsc();

    /** Domain-scoped audit trail, newest first. Equivalent to
     *  {@code SELECT ... WHERE domain = :domain ORDER BY created_at DESC, id}. */
    Flux<ForumAction> findAllByDomainOrderByCreatedAtDescIdAsc(String domain);

    /** SUPERADMIN cross-domain bypass: one actor's actions across every brand, newest
     *  first. Equivalent to {@code ... WHERE actor_subject = :actor ORDER BY created_at DESC, id}. */
    Flux<ForumAction> findAllByActorSubjectOrderByCreatedAtDescIdAsc(String actorSubject);

    /** Domain-scoped: one actor's actions within one brand, newest first. Equivalent to
     *  {@code ... WHERE actor_subject = :actor AND domain = :domain ORDER BY created_at DESC, id}. */
    Flux<ForumAction> findAllByActorSubjectAndDomainOrderByCreatedAtDescIdAsc(String actorSubject, String domain);

    // ── BOUNDED audit-trail reads (anti-DoS LIMIT cap) ──────────────────
    //
    // The {@code GET /bff/forum/admin/audit} surface must NEVER collect the whole
    // forum_action table into memory (an unbounded-table DoS). These reads bound the
    // newest-first scan with {@code LIMIT :limit}; a {@code LIMIT} cannot be expressed
    // by a Spring Data derived finder, so they are static-final {@code @Query} constants
    // (the data-access standard: derived finder OR static-final {@code @Query} constant —
    // never an inline literal). The caller (ForumService) clamps {@code limit} server-side
    // to {@code [1, FORUM_AUDIT_MAX_LIMIT]} with a {@code FORUM_AUDIT_DEFAULT_LIMIT} default.

    /** SUPERADMIN cross-domain bypass, BOUNDED: the whole audit trail, newest first,
     *  capped at {@code :limit} rows. The {@code (domain, created_at)} index (changelog
     *  003) is not selective here, but the {@code LIMIT} caps the scan. */
    @Query(SELECT_NEWEST_LIMIT)
    Flux<ForumAction> findNewest(@Param("limit") int limit);

    /** Domain-scoped, BOUNDED: one brand's audit trail, newest first, capped at
     *  {@code :limit} rows. Backed by the {@code (domain, created_at)} index. */
    @Query(SELECT_NEWEST_BY_DOMAIN_LIMIT)
    Flux<ForumAction> findNewestByDomain(@Param("domain") String domain, @Param("limit") int limit);

    /**
     * Insert an audit row, stamping {@code created_at = now()}, and RETURN the
     * database-generated id. The {@code id} is OMITTED — Postgres fills it from the
     * {@code (gen_random_uuid())::text} column DEFAULT (changelog 004) — and
     * {@code RETURNING id} reads the generated 36-char UUID string back so the facade
     * re-reads the persisted row by it. A {@code now()} INSERT cannot be a derived
     * method, and an {@code INSERT ... RETURNING} is a plain (NON-{@code @Modifying})
     * {@code @Query} returning the new id, bound to a static-final constant (never an
     * inline literal).
     */
    @Query(INSERT_ACTION_RETURNING_ID)
    Mono<String> insertAction(@Param("actor") String actorSubject,
                              @Param("action") String action,
                              @Param("target") String target,
                              @Param("outcome") String outcome,
                              @Param("detail") String detail,
                              @Param("dom") String domain);

    /** The ({@code now()}-stamping) audit INSERT — id OMITTED (filled from the
     *  {@code (gen_random_uuid())::text} DEFAULT), {@code RETURNING id} yields the
     *  DB-generated UUID string. */
    String INSERT_ACTION_RETURNING_ID =
            "INSERT INTO forum_action (actor_subject, action, target, outcome, detail, domain, created_at) "
                    + "VALUES (:actor, :action, :target, :outcome, :detail, :dom, now()) "
                    + "RETURNING id";

    /** The column projection shared by the bounded reads — matches the {@link ForumAction}
     *  record so the rows map back identically to the derived finders. */
    String AUDIT_COLUMNS =
            "id, actor_subject, action, target, outcome, detail, created_at, domain";

    /** SUPERADMIN bounded newest-first read — {@code ORDER BY created_at DESC, id} (the
     *  exact ordering of the derived finders) capped at {@code :limit}. */
    String SELECT_NEWEST_LIMIT =
            "SELECT " + AUDIT_COLUMNS + " FROM forum_action "
                    + "ORDER BY created_at DESC, id LIMIT :limit";

    /** Domain-scoped bounded newest-first read — {@code WHERE domain = :domain
     *  ORDER BY created_at DESC, id} capped at {@code :limit}. */
    String SELECT_NEWEST_BY_DOMAIN_LIMIT =
            "SELECT " + AUDIT_COLUMNS + " FROM forum_action "
                    + "WHERE domain = :domain ORDER BY created_at DESC, id LIMIT :limit";
}
