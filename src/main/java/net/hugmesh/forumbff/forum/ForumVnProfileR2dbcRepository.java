package net.hugmesh.forumbff.forum;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;

/**
 * Reactive (R2DBC) Spring Data store for the {@code forum_vn_profile} table
 * (Liquibase {@code 005}), keyed by the IMMUTABLE Casdoor {@code sub} (the PK).
 * Mirrors {@link ForumUserRoleR2dbcRepository} exactly: DERIVED finders for the
 * reads, and {@code @Query} static-final constants only for the portable
 * UPDATE-then-INSERT upsert legs that no derived method can express (a multi-column
 * SET + {@code now()}).
 *
 * <p>The {@link ForumVnProfileRepository} facade keeps the public method shape (the
 * {@code null}-domain SUPERADMIN bypass + the default-domain overloads); this
 * interface is the data-access layer it delegates to.
 */
public interface ForumVnProfileR2dbcRepository extends ReactiveCrudRepository<ForumVnProfile, String> {

    /** SUPERADMIN cross-domain bypass read: the single profile for a Casdoor subject in
     *  ANY brand (the {@code casdoor_subject} PK is globally-unique). Equivalent to
     *  {@code SELECT ... WHERE casdoor_subject = :sub} (no domain predicate). */
    Mono<ForumVnProfile> findByCasdoorSubject(String casdoorSubject);

    /** Domain-scoped read: the profile for a Casdoor subject WITHIN one brand.
     *  Equivalent to {@code SELECT ... WHERE casdoor_subject = :sub AND domain = :domain}. */
    Mono<ForumVnProfile> findByCasdoorSubjectAndDomain(String casdoorSubject, String domain);

    /** SUPERADMIN cross-domain bypass batch read (the VN reader's author-lookup):
     *  every profile whose subject is in the set, any brand. Equivalent to
     *  {@code SELECT ... WHERE casdoor_subject IN (:subjects)}. */
    Flux<ForumVnProfile> findAllByCasdoorSubjectIn(Collection<String> casdoorSubjects);

    /** Domain-scoped batch read: the profiles for a subject-set WITHIN one brand.
     *  Equivalent to {@code SELECT ... WHERE casdoor_subject IN (:subjects) AND domain = :domain}. */
    Flux<ForumVnProfile> findAllByCasdoorSubjectInAndDomain(Collection<String> casdoorSubjects, String domain);

    /**
     * Portable upsert UPDATE leg — set the presentation fields/domain and bump
     * {@code updated_at} to {@code now()} for an existing subject. Returns the number
     * of rows touched so the facade can INSERT only on a miss (keeps the SQL
     * engine-clean — no ON CONFLICT / MERGE divergence between Postgres and H2). This
     * is a multi-column SET with a DB {@code now()} call, which no derived method can
     * express, so it is a {@code @Query} bound to a static-final constant.
     */
    @Modifying
    @Query(UPDATE_PROFILE)
    Mono<Long> updateProfile(@Param("sub") String casdoorSubject,
                             @Param("sticker") String stickerSlug,
                             @Param("img") String characterImgRef,
                             @Param("vbstyle") String voiceboxStyle,
                             @Param("vbaccent") String voiceboxAccent,
                             @Param("voice") String voiceStyle,
                             @Param("dom") String domain);

    /** Portable upsert INSERT leg — insert a new profile, stamping {@code updated_at}
     *  to {@code now()}. Run only when {@link #updateProfile} touched no row. */
    @Modifying
    @Query(INSERT_PROFILE)
    Mono<Long> insertProfile(@Param("sub") String casdoorSubject,
                             @Param("sticker") String stickerSlug,
                             @Param("img") String characterImgRef,
                             @Param("vbstyle") String voiceboxStyle,
                             @Param("vbaccent") String voiceboxAccent,
                             @Param("voice") String voiceStyle,
                             @Param("dom") String domain);

    /** The UPDATE leg of the portable insert-then-update upsert (Postgres + H2). */
    String UPDATE_PROFILE =
            "UPDATE forum_vn_profile SET sticker_slug = :sticker, character_img_ref = :img, "
                    + "voicebox_style = :vbstyle, voicebox_accent = :vbaccent, voice_style = :voice, "
                    + "domain = :dom, updated_at = now() WHERE casdoor_subject = :sub";

    /** The INSERT leg of the portable insert-then-update upsert (Postgres + H2). */
    String INSERT_PROFILE =
            "INSERT INTO forum_vn_profile (casdoor_subject, sticker_slug, character_img_ref, "
                    + "voicebox_style, voicebox_accent, voice_style, domain, updated_at) "
                    + "VALUES (:sub, :sticker, :img, :vbstyle, :vbaccent, :voice, :dom, now())";
}
