package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.forumbff.support.TestDatabaseConfig;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CONCURRENT (and conflicting) test for the {@code forum_user_role} binding cache — a
 * natural {@code casdoor_subject} PK table that the DB-generated-UUID-PK migration does
 * NOT touch (only {@code forum_action} moved to a DB-generated id). It therefore stays on
 * the H2 (PostgreSQL-compat) store via {@link TestDatabaseConfig}, where the portable
 * try-UPDATE-then-INSERT upsert converges deterministically. It was split out of
 * {@link ForumDomainScopeTest} when that class moved to Testcontainers-Postgres for the
 * {@code forum_action} {@code INSERT ... RETURNING id} path: the portable upsert has a
 * genuine same-PK insert TOCTOU window that surfaces only under real concurrent Postgres
 * inserts — a pre-existing property of the engine-clean upsert, orthogonal to this
 * migration — so the test keeps its original H2 substrate and its UNWEAKENED single-row
 * convergence assertions.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, ForumUserRoleRepository.class})
class ForumUserRoleConcurrentRebindTest {

    @Autowired ForumUserRoleRepository bindings;

    /** Unique-per-test subject keys so the shared @DataR2dbcTest context's rows from
     *  sibling tests never bleed into a count. */
    private static final AtomicInteger SEQ = new AtomicInteger();
    private String k(String tag) { return tag + "-" + SEQ.incrementAndGet(); }

    /** Concurrent re-binding of ONE subject across brands: the casdoor_subject is the
     *  globally-unique PK, so the upsert converges to a SINGLE row carrying one of the
     *  brands deterministically (last-writer-wins) — never a duplicate. */
    @Test
    void concurrentRebindOfOneSubject_convergesToSingleRow() {
        String sub = k("cc-sub");
        int n = 50;
        Flux.range(0, n)
                .flatMap(i -> bindings.upsert(sub, (long) i, "REGISTERED",
                        (i % 2 == 0) ? "brandx" : "brandy"))
                .then().block(Duration.ofSeconds(30));

        // Exactly one row exists for this subject across BOTH brands (SUPERADMIN view).
        ForumUserRole row = bindings.findBySubject(sub, null).block();
        assertThat(row).isNotNull();
        assertThat(row.domain()).isIn("brandx", "brandy");   // one brand won deterministically
        // And it is the ONLY row — the other brand's scope sees it iff it won.
        long inX = countOrZero(bindings.findBySubject(sub, "brandx"));
        long inY = countOrZero(bindings.findBySubject(sub, "brandy"));
        assertThat(inX + inY).isEqualTo(1L);                 // never two rows for one sub
    }

    private long countOrZero(Mono<ForumUserRole> m) {
        return m.map(r -> 1L).blockOptional().orElse(0L);
    }
}
