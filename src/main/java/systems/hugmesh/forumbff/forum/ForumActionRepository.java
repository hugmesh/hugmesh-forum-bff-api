package systems.hugmesh.forumbff.forum;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

/**
 * Reactive (R2DBC) store for the NEW {@code forum_action} audit table — forum-bff's
 * OWN audit trail (NOT mod-bff's {@code mod_action}). The id is app-generated (UUID)
 * so the INSERT is portable (Postgres + H2) and returns the new row. Every forum
 * admin/congruence action is recorded here regardless of the external phpBB outcome.
 * Mirrors the user-bff {@code UserBlockRepository} R2DBC pattern.
 *
 * <p><b>Domain-scoped (Liquibase {@code 003}).</b> Each row carries the brand/tenant
 * {@code domain} (stamped SERVER-SIDE from the actor's validated-issuer brand). The
 * read methods take an optional {@code domain} predicate ({@link DomainScope}) so a
 * forum admin/mod of brand X reads only brand X's trail; a {@code null} domain is the
 * SUPERADMIN cross-domain bypass (no predicate — reads every brand's). The
 * back-compat overloads scope to the platform {@code default} domain so single-tenant
 * clusters + existing callers are unchanged.
 *
 * <p>This is a thin facade over {@link ForumActionR2dbcRepository} (Spring Data
 * reactive repository) — it keeps the prior public method shape (the DB-generated id +
 * read-back) while the actual data access goes through derived, ordering-exact finders
 * + the {@code INSERT ... RETURNING id} {@code @Query} constant.
 *
 * <p>DB-GENERATED UUID PK (the org-wide migration, mod-bff #36 / admin-bff #133): the
 * id is no longer minted in Java ({@code UUID.randomUUID()}). The INSERT omits id, the
 * {@code forum_action.id} column DEFAULT {@code (gen_random_uuid())::text} fills it, and
 * {@code RETURNING id} reads the generated id back — which the facade then re-reads the
 * persisted row by. The {@code domain} stamping / SUPERADMIN bypass / read-back shape
 * are unchanged.
 */
@Repository
public class ForumActionRepository {

    private final ForumActionR2dbcRepository repo;

    public ForumActionRepository(ForumActionR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — stamps the platform {@code default} domain. */
    public Mono<ForumAction> record(String actorSubject, String action, String target,
                                    String outcome, String detail) {
        return record(actorSubject, action, target, outcome, detail, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Record an action (DB-generated id) in the actor's domain and return the
     * persisted row. The {@code domain} is stamped SERVER-SIDE (the actor's
     * validated-issuer brand), never a request field. A SUPERADMIN ({@code domain}
     * null/blank) defaults the row to the platform {@code default} domain so a stamped
     * audit row always carries a concrete brand.
     *
     * <p>The id is no longer minted here — the INSERT omits it, Postgres fills it from
     * the {@code (gen_random_uuid())::text} column DEFAULT (changelog 004), and
     * {@code RETURNING id} yields the generated id which we re-read the row back by.
     */
    public Mono<ForumAction> record(String actorSubject, String action, String target,
                                    String outcome, String detail, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.insertAction(actorSubject, action, target, outcome,
                        detail == null ? "" : detail, dom)
                .flatMap(repo::findById);
    }

    /** Back-compat overload — scopes the audit trail to the platform {@code default} domain. */
    public Flux<ForumAction> list() {
        return list(DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The audit trail for one brand (newest first); a {@code null} domain is the
     *  SUPERADMIN cross-domain bypass (every brand's actions). */
    public Flux<ForumAction> list(String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findAllByOrderByCreatedAtDescIdAsc()
                : repo.findAllByDomainOrderByCreatedAtDescIdAsc(domain);
    }

    /**
     * BOUNDED audit trail for one brand (newest first), capped at {@code limit} rows; a
     * {@code null} domain is the SUPERADMIN cross-domain bypass (every brand's actions,
     * still capped). This is the anti-DoS read backing {@code GET /bff/forum/admin/audit}
     * — the caller ({@link ForumService}) clamps {@code limit} server-side BEFORE calling,
     * so a row-by-row table scan can never collect the WHOLE table into memory.
     *
     * @param domain the brand to scope to, or {@code null}/blank for the SUPERADMIN bypass
     * @param limit  the (already-clamped, server-side) hard cap on rows returned
     * @return at most {@code limit} {@link ForumAction} rows, newest first
     */
    public Flux<ForumAction> list(String domain, int limit) {
        return DomainScope.isUnscoped(domain)
                ? repo.findNewest(limit)
                : repo.findNewestByDomain(domain, limit);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<ForumAction> listByActor(String actorSubject) {
        return listByActor(actorSubject, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The actions performed by one actor within a brand; a {@code null} domain is
     *  the SUPERADMIN cross-domain bypass (the actor's actions across every brand). */
    public Flux<ForumAction> listByActor(String actorSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findAllByActorSubjectOrderByCreatedAtDescIdAsc(actorSubject)
                : repo.findAllByActorSubjectAndDomainOrderByCreatedAtDescIdAsc(actorSubject, domain);
    }
}
