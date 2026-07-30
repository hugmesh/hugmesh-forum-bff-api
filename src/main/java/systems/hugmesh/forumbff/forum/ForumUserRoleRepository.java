package systems.hugmesh.forumbff.forum;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

/**
 * Reactive (R2DBC) store for {@code forum_user_role} — keyed by the immutable Casdoor
 * {@code sub}. Used to cache the phpBB user binding + last computed group membership so
 * the BFF can resolve the binding without round-tripping the extension on every call,
 * and to drive the declarative group sync's last-writer-wins race resolution.
 *
 * <p><b>Domain-scoped (Liquibase {@code 003}).</b> Each binding carries the brand/tenant
 * {@code domain} (stamped SERVER-SIDE from the subject's validated-issuer brand). The
 * read takes an optional {@code domain} predicate ({@link DomainScope}) so a forum
 * admin/mod of brand X resolves only brand X's bindings; a {@code null} domain is the
 * SUPERADMIN cross-domain bypass. The {@code casdoor_subject} stays the globally-unique
 * PK (the Casdoor sub is already collision-safe), so the upsert keys on subject alone
 * and STAMPS the domain on the row; back-compat overloads scope to the platform
 * {@code default} domain so single-tenant clusters + existing callers are unchanged.
 *
 * <p>This is a thin facade over {@link ForumUserRoleR2dbcRepository} (Spring Data
 * reactive repository) — it keeps the prior public method shape while the actual data
 * access goes through derived finders + the portable-upsert {@code @Query} constants.
 */
@Repository
public class ForumUserRoleRepository {

    private final ForumUserRoleR2dbcRepository repo;

    public ForumUserRoleRepository(ForumUserRoleR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<ForumUserRole> findBySubject(String casdoorSubject) {
        return findBySubject(casdoorSubject, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The cached binding for a Casdoor subject within a brand, if any; a {@code null}
     *  domain is the SUPERADMIN cross-domain bypass (the subject's binding in any
     *  brand). */
    public Mono<ForumUserRole> findBySubject(String casdoorSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByCasdoorSubject(casdoorSubject)
                : repo.findByCasdoorSubjectAndDomain(casdoorSubject, domain);
    }

    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<ForumUserRole> upsert(String casdoorSubject, Long phpbbUserId, String groupMembership) {
        return upsert(casdoorSubject, phpbbUserId, groupMembership, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Upsert the binding + group membership for a Casdoor subject, STAMPING the brand
     * {@code domain} (server-derived; a SUPERADMIN's null/blank defaults to the
     * platform {@code default} domain so a stamped binding always carries a concrete
     * brand). The {@code casdoor_subject} is the globally-unique key (the Casdoor sub
     * is already collision-safe), so the upsert keys on subject and writes the domain
     * as a stamped column. Portable upsert (Postgres + H2): try UPDATE first, INSERT
     * only when no row was touched, so the SQL stays engine-clean (no ON CONFLICT /
     * MERGE divergence).
     */
    public Mono<ForumUserRole> upsert(String casdoorSubject, Long phpbbUserId, String groupMembership,
                                      String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.updateBinding(casdoorSubject, phpbbUserId, groupMembership, dom)
                .flatMap(updated -> updated > 0
                        ? Mono.empty()
                        : repo.insertBinding(casdoorSubject, phpbbUserId, groupMembership, dom).then())
                // Re-read scoped to the stamped domain so the returned row reflects the
                // brand it now lives in (a moved-brand binding never reads back as default).
                .then(findBySubject(casdoorSubject, dom));
    }
}
