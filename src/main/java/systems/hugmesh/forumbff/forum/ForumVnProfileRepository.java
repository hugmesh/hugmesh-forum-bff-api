package systems.hugmesh.forumbff.forum;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.tenancy.DomainScope;

import java.util.Collection;

/**
 * Reactive (R2DBC) store for {@code forum_vn_profile} — the visual-novel reading-mode
 * presentation profile, keyed by the immutable Casdoor {@code sub}. Read on the VN
 * reader's author-lookup path (batched) and on the caller's own {@code /me} surface;
 * written only by the owner (the controller derives the subject from the JWT, NEVER
 * the body).
 *
 * <p><b>Domain-scoped (Liquibase {@code 005}, following {@code 003}).</b> Each profile
 * carries the brand/tenant {@code domain} (stamped SERVER-SIDE from the subject's
 * validated-issuer brand). The reads take an optional {@code domain} predicate
 * ({@link DomainScope}); a {@code null} domain is the SUPERADMIN cross-domain bypass.
 * The {@code casdoor_subject} stays the globally-unique PK (the Casdoor sub is already
 * collision-safe), so the upsert keys on subject alone and STAMPS the domain on the
 * row; back-compat overloads scope to the platform {@code default} domain so
 * single-tenant clusters are unchanged — the same semantics as
 * {@link ForumUserRoleRepository}.
 *
 * <p>This is a thin facade over {@link ForumVnProfileR2dbcRepository} (Spring Data
 * reactive repository) — the actual data access goes through derived finders + the
 * portable-upsert {@code @Query} constants.
 */
@Repository
public class ForumVnProfileRepository {

    private final ForumVnProfileR2dbcRepository repo;

    public ForumVnProfileRepository(ForumVnProfileR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<ForumVnProfile> findBySubject(String casdoorSubject) {
        return findBySubject(casdoorSubject, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The profile for a Casdoor subject within a brand, if any; a {@code null}
     *  domain is the SUPERADMIN cross-domain bypass (the subject's profile in any
     *  brand). */
    public Mono<ForumVnProfile> findBySubject(String casdoorSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByCasdoorSubject(casdoorSubject)
                : repo.findByCasdoorSubjectAndDomain(casdoorSubject, domain);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<ForumVnProfile> findBySubjects(Collection<String> casdoorSubjects) {
        return findBySubjects(casdoorSubjects, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The profiles for a subject-set within a brand (the VN reader's batched
     *  author-lookup); subjects with no row are simply absent from the result. A
     *  {@code null} domain is the SUPERADMIN cross-domain bypass. */
    public Flux<ForumVnProfile> findBySubjects(Collection<String> casdoorSubjects, String domain) {
        if (casdoorSubjects == null || casdoorSubjects.isEmpty()) {
            return Flux.empty();
        }
        return DomainScope.isUnscoped(domain)
                ? repo.findAllByCasdoorSubjectIn(casdoorSubjects)
                : repo.findAllByCasdoorSubjectInAndDomain(casdoorSubjects, domain);
    }

    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<ForumVnProfile> upsert(String casdoorSubject, String stickerSlug, String characterImgRef,
                                       String voiceboxStyle, String voiceboxAccent, String voiceStyle) {
        return upsert(casdoorSubject, stickerSlug, characterImgRef, voiceboxStyle, voiceboxAccent,
                voiceStyle, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Upsert the VN profile for a Casdoor subject, STAMPING the brand {@code domain}
     * (server-derived; a SUPERADMIN's null/blank defaults to the platform
     * {@code default} domain so a stamped profile always carries a concrete brand).
     * The {@code casdoor_subject} is the globally-unique key (the Casdoor sub is
     * already collision-safe), so the upsert keys on subject and writes the domain as
     * a stamped column. Portable upsert (Postgres + H2): try UPDATE first, INSERT only
     * when no row was touched, so the SQL stays engine-clean (no ON CONFLICT / MERGE
     * divergence) — the same shape as {@link ForumUserRoleRepository#upsert}.
     */
    public Mono<ForumVnProfile> upsert(String casdoorSubject, String stickerSlug, String characterImgRef,
                                       String voiceboxStyle, String voiceboxAccent, String voiceStyle,
                                       String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.updateProfile(casdoorSubject, stickerSlug, characterImgRef,
                        voiceboxStyle, voiceboxAccent, voiceStyle, dom)
                .flatMap(updated -> updated > 0
                        ? Mono.empty()
                        : repo.insertProfile(casdoorSubject, stickerSlug, characterImgRef,
                                voiceboxStyle, voiceboxAccent, voiceStyle, dom).then())
                // Re-read scoped to the stamped domain so the returned row reflects the
                // brand it now lives in (a moved-brand profile never reads back as default).
                .then(findBySubject(casdoorSubject, dom));
    }
}
