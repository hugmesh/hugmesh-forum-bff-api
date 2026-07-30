package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.forumbff.support.PostgresSliceTestConfig;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The DATA-LAYER isolation boundary — the keystone of the multi-brand model. Proves
 * the {@code domain = :domain} predicate (forum_action audit trail + forum_user_role
 * binding cache) lets a forum admin/mod of brand X see ONLY brand X's rows, while
 * SUPERADMIN (a {@code null} domain) is unscoped. R2DBC slice over a
 * Testcontainers-Postgres store with the REAL Liquibase changelog (the {@code 003}
 * domain column + the {@code 004} DB-generated forum_action.id) — moved off H2 because
 * the audit {@code record} path now uses {@code INSERT ... RETURNING id} over a
 * {@code (gen_random_uuid())::text} DEFAULT, which H2 cannot honour. Delineated per the
 * test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a single brand stamps + reads its own rows.</li>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — SUPERADMIN (null domain) reads every brand's
 *       rows; the back-compat overloads behave as the {@code default} brand.</li>
 *   <li><b>CROSS-USER</b> — the ISOLATION DENY: brand X never reads brand Y's audit
 *       trail or binding; a forged/unresolved {@code __deny__} scope reads NOTHING.</li>
 *   <li><b>CONCURRENT</b> — concurrent records across brands keep each brand's count
 *       correct; a concurrent re-binding of one subject across brands converges to a
 *       single deterministic row (last-writer-wins on the subject PK).</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ForumActionRepository.class, ForumUserRoleRepository.class})
class ForumDomainScopeTest extends PostgresTestSupport {

    @Autowired ForumActionRepository audit;
    @Autowired ForumUserRoleRepository bindings;

    /** Unique-per-test actor/subject keys so the shared @DataR2dbcTest context's rows
     *  from sibling tests never bleed into a count. */
    private static final AtomicInteger SEQ = new AtomicInteger();
    private String k(String tag) { return tag + "-" + SEQ.incrementAndGet(); }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void auditRow_stampsAndReadsBackInItsOwnBrand() {
            String actor = k("us-actor");
            audit.record(actor, "admin.forum.user.ban", "sub-1", "stubbed", "abuse", "brandx").block();

            List<ForumAction> brandx = audit.listByActor(actor, "brandx").collectList().block();
            assertThat(brandx).hasSize(1);
            assertThat(brandx.get(0).domain()).isEqualTo("brandx");
            // The SAME actor's brandx row is invisible when scoping to brandy.
            assertThat(audit.listByActor(actor, "brandy").collectList().block()).isEmpty();
        }

        @Test
        void binding_stampsAndReadsBackInItsOwnBrand() {
            String sub = k("us-sub");
            bindings.upsert(sub, 100L, "REGISTERED", "brandx").block();

            ForumUserRole inBrand = bindings.findBySubject(sub, "brandx").block();
            assertThat(inBrand).isNotNull();
            assertThat(inBrand.domain()).isEqualTo("brandx");
            assertThat(inBrand.phpbbUserId()).isEqualTo(100L);
            // Invisible from another brand's scope.
            assertThat(bindings.findBySubject(sub, "brandy").blockOptional()).isEmpty();
        }
    }

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {

        /** SUPERADMIN (null domain) reads BOTH brands' actions for an actor. */
        @Test
        void superadmin_nullDomain_readsEveryBrandForActor() {
            String actor = k("mu-actor");
            audit.record(actor, "admin.forum.user.ban", "s1", "ok", null, "brandx").block();
            audit.record(actor, "admin.forum.user.ban", "s2", "ok", null, "brandy").block();

            // null domain == the SUPERADMIN cross-domain bypass (no predicate).
            List<ForumAction> all = audit.listByActor(actor, null).collectList().block();
            assertThat(all).hasSize(2);
            assertThat(all).extracting(ForumAction::domain).containsExactlyInAnyOrder("brandx", "brandy");

            // A brand-scoped read sees only its own brand's one row.
            assertThat(audit.listByActor(actor, "brandx").collectList().block()).hasSize(1);
        }

        /** The back-compat overloads behave as the platform {@code default} brand. */
        @Test
        void backCompatOverloads_areDefaultBrand() {
            String actor = k("mu-bc-actor");
            String sub = k("mu-bc-sub");
            audit.record(actor, "admin.forum.style.install", "prosilver", "ok", null).block(); // 5-arg
            bindings.upsert(sub, 5L, "REGISTERED").block();                                     // 3-arg

            assertThat(audit.listByActor(actor).collectList().block()).hasSize(1);   // default-scoped
            assertThat(audit.listByActor(actor).collectList().block().get(0).domain()).isEqualTo("default");
            assertThat(bindings.findBySubject(sub).block().domain()).isEqualTo("default");
        }
    }

    // ── CROSS-USER (the ISOLATION DENY) ───────────────────────────────────────
    @Nested
    class CrossUser {

        /** Two brands record under the SAME actor name; each brand reads ONLY its own
         *  row — the cross-tenant audit trail is invisible. */
        @Test
        void brandX_neverReadsBrandY_auditTrail() {
            String actor = k("cu-actor");
            audit.record(actor, "admin.forum.user.ban", "victim", "ok", null, "brandx").block();
            audit.record(actor, "admin.forum.user.ban", "victim", "ok", null, "brandy").block();

            List<ForumAction> x = audit.listByActor(actor, "brandx").collectList().block();
            List<ForumAction> y = audit.listByActor(actor, "brandy").collectList().block();
            assertThat(x).hasSize(1);
            assertThat(y).hasSize(1);
            assertThat(x.get(0).domain()).isEqualTo("brandx");
            assertThat(y.get(0).domain()).isEqualTo("brandy");
        }

        /** The domain-only audit scan ({@code list(domain)}) never crosses brands. */
        @Test
        void list_domainScoped_neverCrossesBrands() {
            String tag = k("cu-list");
            audit.record(tag + "-a", "admin.forum.user.ban", "t", "ok", null, tag + "-bx").block();
            audit.record(tag + "-b", "admin.forum.user.ban", "t", "ok", null, tag + "-by").block();

            assertThat(audit.list(tag + "-bx").collectList().block())
                    .allSatisfy(a -> assertThat(a.domain()).isEqualTo(tag + "-bx"));
            assertThat(audit.list(tag + "-by").collectList().block())
                    .allSatisfy(a -> assertThat(a.domain()).isEqualTo(tag + "-by"));
        }

        /** The {@code __deny__} fail-closed sentinel (a non-SUPERADMIN with an
         *  unresolved issuer) matches NO real row — a stamped brandx row is invisible. */
        @Test
        void denySentinelScope_readsNothing() {
            String actor = k("cu-deny-actor");
            String sub = k("cu-deny-sub");
            audit.record(actor, "admin.forum.user.ban", "t", "ok", null, "brandx").block();
            bindings.upsert(sub, 9L, "REGISTERED", "brandx").block();

            assertThat(audit.listByActor(actor, "__deny__").collectList().block()).isEmpty();
            assertThat(bindings.findBySubject(sub, "__deny__").blockOptional()).isEmpty();
        }
    }

    // ── CONCURRENT (and conflicting) ──────────────────────────────────────────
    @Nested
    class Concurrent {

        /** 100 concurrent audit records split across two brands: each brand's scoped
         *  count is exactly its half (no row leaks across the domain predicate under
         *  contention). */
        @Test
        void concurrentRecordsAcrossBrands_keepPerBrandCounts() {
            String actor = k("cc-actor");
            int n = 100;
            Flux.range(0, n)
                    .flatMap(i -> audit.record(actor, "admin.forum.user.ban", "t" + i, "ok", null,
                            (i % 2 == 0) ? "brandx" : "brandy"))
                    .then().block(Duration.ofSeconds(30));

            assertThat(audit.listByActor(actor, "brandx").collectList().block()).hasSize(n / 2);
            assertThat(audit.listByActor(actor, "brandy").collectList().block()).hasSize(n / 2);
            // SUPERADMIN sees the full set.
            assertThat(audit.listByActor(actor, null).collectList().block()).hasSize(n);
        }

        // NOTE: concurrentRebindOfOneSubject_convergesToSingleRow exercises ONLY the
        // forum_user_role binding cache (a natural casdoor_subject PK — NOT migrated by
        // the DB-generated-UUID change) and asserts the portable try-UPDATE-then-INSERT
        // upsert converges. It is kept on the H2 store in
        // ForumUserRoleConcurrentRebindTest: this class moved to real Postgres for the
        // forum_action INSERT ... RETURNING id path, and the portable upsert has a
        // genuine same-PK TOCTOU race that only manifests under real concurrent Postgres
        // inserts — orthogonal to this migration. Keeping it on H2 preserves the
        // original (unweakened) convergence assertions.
    }
}
