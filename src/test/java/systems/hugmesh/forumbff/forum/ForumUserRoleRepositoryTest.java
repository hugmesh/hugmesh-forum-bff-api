package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.hugmesh.forumbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link ForumUserRoleRepository} (the forum_user_role binding
 * cache keyed by the IMMUTABLE Casdoor sub). Verifies the portable upsert
 * (insert-then-update) round-trip and that distinct Casdoor subjects are distinct
 * rows (collision-safe by sub, never localpart).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, ForumUserRoleRepository.class})
class ForumUserRoleRepositoryTest {

    @Autowired ForumUserRoleRepository repo;

    @Test
    void upsert_insertsThenUpdates_keyedBySubject() {
        ForumUserRole inserted = repo.upsert("sub-1", 100L, "REGISTERED").block();
        assertThat(inserted.casdoorSubject()).isEqualTo("sub-1");
        assertThat(inserted.phpbbUserId()).isEqualTo(100L);
        assertThat(inserted.groupMembership()).isEqualTo("REGISTERED");

        // Same subject -> UPDATE (still one row), promoted group.
        ForumUserRole promoted = repo.upsert("sub-1", 100L, "GLOBAL_MODERATORS").block();
        assertThat(promoted.groupMembership()).isEqualTo("GLOBAL_MODERATORS");
        assertThat(repo.findBySubject("sub-1").block().groupMembership()).isEqualTo("GLOBAL_MODERATORS");
    }

    @Test
    void distinctSubjects_areDistinctRows() {
        repo.upsert("sub-A", 1L, "REGISTERED").block();
        repo.upsert("sub-B", 2L, "REGISTERED").block();
        assertThat(repo.findBySubject("sub-A").block().phpbbUserId()).isEqualTo(1L);
        assertThat(repo.findBySubject("sub-B").block().phpbbUserId()).isEqualTo(2L);
    }

    @Test
    void findBySubject_missingIsEmpty() {
        assertThat(repo.findBySubject("nobody").blockOptional()).isEmpty();
    }
}
