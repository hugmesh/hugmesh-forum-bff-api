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
 * R2DBC slice test for {@link ForumActionRepository} over a Testcontainers-Postgres
 * store that Liquibase applies the REAL production changelog over (the
 * {@link PostgresSliceTestConfig} pattern). Verifies the record/list round-trip + that
 * the audit row carries the (stubbed/degraded/ok) outcome — proving a stubbed phpBB ban
 * is still auditable — AND the multi-brand DATA-LAYER isolation boundary: a forum admin
 * of brand X reads ONLY brand X's audit trail, SUPERADMIN ({@code null} domain) reads
 * every brand's, and an unresolved / forged scope reads NOTHING. Each {@code record}
 * round-trip now also proves the id is DB-GENERATED (changelog 004) and read back via
 * {@code INSERT ... RETURNING id}.
 *
 * <p>Moved off the H2 PostgreSQL-compat store ({@code TestDatabaseConfig}) because the
 * DB-generated-id migration needs {@code pgcrypto}/{@code gen_random_uuid()} and a
 * reliable {@code INSERT ... RETURNING}, NEITHER of which H2 provides. The tests still
 * scope by unique actor/domain names so the per-class container db's rows don't bleed
 * across methods.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ForumActionRepository.class})
class ForumActionRepositoryTest extends PostgresTestSupport {

    @Autowired ForumActionRepository repo;

    @Test
    void recordAndList_roundTrip_carriesStubbedOutcome() {
        ForumAction saved = repo.record("roundTrip-actor", "admin.forum.user.ban", "sub-9", "stubbed", "abuse").block();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.outcome()).isEqualTo("stubbed");
        assertThat(saved.createdAt()).isNotNull();
        // The back-compat overload stamps the platform default domain.
        assertThat(saved.domain()).isEqualTo("default");

        // Scope the assertion to THIS test's actor so the shared @DataR2dbcTest context
        // (rows from sibling tests) doesn't affect the count.
        List<ForumAction> mine = repo.listByActor("roundTrip-actor").collectList().block();
        assertThat(mine).hasSize(1);
        assertThat(mine.get(0).action()).isEqualTo("admin.forum.user.ban");
        assertThat(mine.get(0).target()).isEqualTo("sub-9");
    }

    @Test
    void listByActor_isActorScoped() {
        // Distinct actor names per test so the shared @DataR2dbcTest context's rows
        // from other tests don't bleed into the by-actor count.
        repo.record("actorScoped-a", "admin.forum.style.install", "prosilver", "ok", null).block();
        repo.record("actorScoped-b", "admin.forum.user.ban", "sub-1", "stubbed", null).block();

        assertThat(repo.listByActor("actorScoped-a").collectList().block()).hasSize(1);
        assertThat(repo.listByActor("actorScoped-b").collectList().block()).hasSize(1);
    }

    // ── DOMAIN ISOLATION ─────────────────────────────────────────────

    /** USER-SITUATIONAL: a row stamps + reads back in its OWN brand and is invisible
     *  from another brand's scope. */
    @Test
    void auditRow_stampsAndReadsBackInItsOwnBrand() {
        repo.record("dom-actor", "admin.forum.user.ban", "sub-1", "stubbed", "abuse", "brandx").block();

        List<ForumAction> brandx = repo.listByActor("dom-actor", "brandx").collectList().block();
        assertThat(brandx).hasSize(1);
        assertThat(brandx.get(0).domain()).isEqualTo("brandx");
        // The SAME actor's brandx row is invisible when scoping to brandy.
        assertThat(repo.listByActor("dom-actor", "brandy").collectList().block()).isEmpty();
    }

    /** CROSS-USER (the ISOLATION DENY): the domain-only audit scan never crosses
     *  brands — the keystone of the fix. Brand X's whole-trail read cannot see brand
     *  Y's rows recorded under the SAME actor name. */
    @Test
    void list_domainScoped_neverCrossesBrands() {
        repo.record("xbrand-a", "admin.forum.user.ban", "victim", "ok", null, "iso-bx").block();
        repo.record("xbrand-b", "admin.forum.user.ban", "victim", "ok", null, "iso-by").block();

        List<ForumAction> x = repo.list("iso-bx").collectList().block();
        List<ForumAction> y = repo.list("iso-by").collectList().block();
        assertThat(x).hasSize(1);
        assertThat(y).hasSize(1);
        assertThat(x.get(0).domain()).isEqualTo("iso-bx");
        assertThat(y.get(0).domain()).isEqualTo("iso-by");
        // And neither brand's scoped read contains the other's row.
        assertThat(x).allSatisfy(a -> assertThat(a.domain()).isEqualTo("iso-bx"));
        assertThat(y).allSatisfy(a -> assertThat(a.domain()).isEqualTo("iso-by"));
    }

    /** MULTIUSER-SITUATIONAL: SUPERADMIN (the {@code null} domain bypass) reads BOTH
     *  brands' actions for an actor; a brand-scoped read sees only its own. */
    @Test
    void superadmin_nullDomain_readsEveryBrandForActor() {
        repo.record("su-actor", "admin.forum.user.ban", "s1", "ok", null, "su-bx").block();
        repo.record("su-actor", "admin.forum.user.ban", "s2", "ok", null, "su-by").block();

        List<ForumAction> all = repo.listByActor("su-actor", null).collectList().block();
        assertThat(all).hasSize(2);
        assertThat(all).extracting(ForumAction::domain).containsExactlyInAnyOrder("su-bx", "su-by");
        assertThat(repo.listByActor("su-actor", "su-bx").collectList().block()).hasSize(1);
    }

    /** CROSS-USER: the {@code __deny__} fail-closed sentinel (a non-SUPERADMIN with an
     *  unresolved/forged issuer scope) matches NO real row — a stamped brandx row is
     *  invisible. This is what stops an unresolved-issuer caller from reaching another
     *  brand's trail. */
    @Test
    void denySentinelScope_readsNothing() {
        repo.record("deny-actor", "admin.forum.user.ban", "t", "ok", null, "brandx").block();

        assertThat(repo.listByActor("deny-actor", "__deny__").collectList().block()).isEmpty();
        assertThat(repo.list("__deny__").collectList().block()).isEmpty();
    }

    // ── BOUNDED audit trail (anti-DoS LIMIT) ─────────────────────────────

    /** (c) NEWEST-FIRST + (b) LIMIT BOUND: the bounded {@code list(domain, limit)} reads
     *  at most {@code limit} rows, ordered newest-first ({@code created_at DESC}). Records
     *  more rows than the cap into a dedicated brand, then proves the read returns exactly
     *  the cap and that the rows are the NEWEST ones in descending recency. */
    @Test
    void boundedList_capsRowsAndReturnsNewestFirst() {
        String dom = "lim-brand";
        // 5 rows; the LAST recorded ("ban-4") is the newest (created_at = now() at insert).
        for (int i = 0; i < 5; i++) {
            repo.record("lim-actor", "admin.forum.user.ban", "ban-" + i, "ok", null, dom).block();
        }

        // Cap below the row count -> exactly `limit` rows, the NEWEST first.
        List<ForumAction> capped = repo.list(dom, 2).collectList().block();
        assertThat(capped).hasSize(2);
        assertThat(capped).allSatisfy(a -> assertThat(a.domain()).isEqualTo(dom));
        // created_at strictly non-increasing == newest-first.
        assertThat(capped.get(0).createdAt()).isAfterOrEqualTo(capped.get(1).createdAt());
        // The newest row recorded was the LAST one (ban-4); it must be first in the cap.
        assertThat(capped.get(0).target()).isEqualTo("ban-4");

        // A cap >= the row count returns ALL of this brand's rows (still newest-first).
        List<ForumAction> all = repo.list(dom, 100).collectList().block();
        assertThat(all).hasSize(5);
        assertThat(all.get(0).target()).isEqualTo("ban-4");
        assertThat(all.get(all.size() - 1).target()).isEqualTo("ban-0");
    }

    /** SUPERADMIN bounded bypass ({@code null} domain) is ALSO capped — the cross-domain
     *  whole-trail read can never collect the whole table either. */
    @Test
    void boundedList_superadminNullDomain_isAlsoCapped() {
        for (int i = 0; i < 4; i++) {
            repo.record("su-lim-actor", "admin.forum.user.ban", "t-" + i, "ok", null, "su-lim-" + i).block();
        }

        List<ForumAction> capped = repo.list(null, 3).collectList().block();
        assertThat(capped).hasSize(3);
        // Newest-first across brands (created_at DESC).
        assertThat(capped.get(0).createdAt()).isAfterOrEqualTo(capped.get(capped.size() - 1).createdAt());
    }
}
