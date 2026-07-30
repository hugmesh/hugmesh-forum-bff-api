package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.forumbff.support.PostgresSliceTestConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link ForumVnProfileRepository} over a Testcontainers-Postgres
 * store that Liquibase applies the REAL production changelog over (the
 * {@link PostgresSliceTestConfig} pattern, following {@link ForumActionRepositoryTest}).
 * Verifies the portable UPDATE-then-INSERT upsert round-trip (insert, then in-place
 * update including null-clearing an optional field), the batched
 * {@code findAllByCasdoorSubjectIn} lookup (missing subjects simply absent), and the
 * multi-brand DATA-LAYER scoping: a brand-stamped row is invisible from another
 * brand's scope, SUPERADMIN ({@code null} domain) reads across brands, and the
 * {@code __deny__} fail-closed sentinel matches nothing.
 *
 * <p>Tests scope by unique subject names so the shared per-class container db's rows
 * don't bleed across methods (the ForumActionRepositoryTest convention).
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ForumVnProfileRepository.class})
class ForumVnProfileRepositoryTest extends PostgresTestSupport {

    @Autowired ForumVnProfileRepository repo;

    @Test
    void upsert_insertsThenUpdates_keyedBySubject() {
        ForumVnProfile inserted = repo.upsert("vn-sub-1", "dragon", "/bff/user/media/img-1.png",
                "retro", "#aa11ff", "robot").block();
        assertThat(inserted.casdoorSubject()).isEqualTo("vn-sub-1");
        assertThat(inserted.stickerSlug()).isEqualTo("dragon");
        assertThat(inserted.characterImgRef()).isEqualTo("/bff/user/media/img-1.png");
        assertThat(inserted.voiceboxStyle()).isEqualTo("retro");
        assertThat(inserted.voiceboxAccent()).isEqualTo("#aa11ff");
        assertThat(inserted.voiceStyle()).isEqualTo("robot");
        assertThat(inserted.updatedAt()).isNotNull();
        // The back-compat overload stamps the platform default domain.
        assertThat(inserted.domain()).isEqualTo("default");

        // Same subject -> UPDATE (still one row): restyled, and the nullable fields
        // CLEAR when null is written (the contract's "null clears" semantics).
        ForumVnProfile updated = repo.upsert("vn-sub-1", null, null, "classic", null, null).block();
        assertThat(updated.stickerSlug()).isNull();
        assertThat(updated.characterImgRef()).isNull();
        assertThat(updated.voiceboxStyle()).isEqualTo("classic");
        assertThat(updated.voiceboxAccent()).isNull();
        assertThat(updated.voiceStyle()).isNull();
        assertThat(updated.updatedAt()).isAfterOrEqualTo(inserted.updatedAt());
        assertThat(repo.findBySubject("vn-sub-1").block().voiceboxStyle()).isEqualTo("classic");
    }

    @Test
    void findBySubject_missingIsEmpty() {
        assertThat(repo.findBySubject("vn-nobody").blockOptional()).isEmpty();
    }

    @Test
    void findBySubjects_returnsOnlyExistingRows() {
        repo.upsert("vn-in-a", "cat", null, "neon", "#123abc", "warm").block();
        repo.upsert("vn-in-b", "dog", null, "glass", null, null).block();

        List<ForumVnProfile> found = repo
                .findBySubjects(List.of("vn-in-a", "vn-in-b", "vn-in-missing"))
                .collectList().block();
        assertThat(found).hasSize(2);
        assertThat(found).extracting(ForumVnProfile::casdoorSubject)
                .containsExactlyInAnyOrder("vn-in-a", "vn-in-b");
        // The missing subject is simply ABSENT — no placeholder row.
    }

    // ── DOMAIN SCOPING (same semantics as ForumUserRoleRepository) ──────

    @Test
    void profile_stampsAndReadsBackInItsOwnBrand() {
        repo.upsert("vn-dom-1", "fox", null, "paper", null, null, "vn-brandx").block();

        ForumVnProfile brandx = repo.findBySubject("vn-dom-1", "vn-brandx").block();
        assertThat(brandx.domain()).isEqualTo("vn-brandx");
        // The SAME subject's brandx row is invisible when scoping to brandy…
        assertThat(repo.findBySubject("vn-dom-1", "vn-brandy").blockOptional()).isEmpty();
        // …and from the fail-closed __deny__ sentinel scope.
        assertThat(repo.findBySubject("vn-dom-1", "__deny__").blockOptional()).isEmpty();
        // SUPERADMIN (null domain) bypasses the predicate.
        assertThat(repo.findBySubject("vn-dom-1", null).block().casdoorSubject()).isEqualTo("vn-dom-1");
    }

    @Test
    void findBySubjects_isDomainScoped_withSuperadminBypass() {
        repo.upsert("vn-multi-a", null, null, "classic", null, null, "vn-iso-bx").block();
        repo.upsert("vn-multi-b", null, null, "classic", null, null, "vn-iso-by").block();

        List<String> subjects = List.of("vn-multi-a", "vn-multi-b");
        // Brand-scoped: each brand sees only its own row.
        assertThat(repo.findBySubjects(subjects, "vn-iso-bx").collectList().block())
                .extracting(ForumVnProfile::casdoorSubject).containsExactly("vn-multi-a");
        assertThat(repo.findBySubjects(subjects, "vn-iso-by").collectList().block())
                .extracting(ForumVnProfile::casdoorSubject).containsExactly("vn-multi-b");
        // SUPERADMIN (null domain) reads across brands.
        assertThat(repo.findBySubjects(subjects, null).collectList().block()).hasSize(2);
        // The fail-closed sentinel matches nothing.
        assertThat(repo.findBySubjects(subjects, "__deny__").collectList().block()).isEmpty();
    }

    @Test
    void upsert_restampsDomain_andReadsBackInNewBrand() {
        repo.upsert("vn-move-1", null, null, "classic", null, null, "vn-old-brand").block();
        // The upsert keys on subject alone (globally-unique PK) and STAMPS the domain:
        // a re-upsert under a new brand MOVES the row, never duplicates it.
        ForumVnProfile moved = repo.upsert("vn-move-1", null, null, "neon", null, null, "vn-new-brand").block();
        assertThat(moved.domain()).isEqualTo("vn-new-brand");
        assertThat(moved.voiceboxStyle()).isEqualTo("neon");
        assertThat(repo.findBySubject("vn-move-1", "vn-old-brand").blockOptional()).isEmpty();
    }
}
