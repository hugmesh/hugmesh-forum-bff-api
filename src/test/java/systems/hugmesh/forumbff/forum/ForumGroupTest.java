package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Casdoor role -> phpBB group mapping (the load-bearing role table):
 * <ul>
 *   <li>ROLE_ADMIN -> ADMINISTRATORS ALWAYS (even without ROLE_FORUM);</li>
 *   <li>ROLE_MOD -> GLOBAL_MODERATORS iff ALSO ROLE_FORUM;</li>
 *   <li>ROLE_FORUM alone -> REGISTERED;</li>
 *   <li>none -> NONE (no access).</li>
 * </ul>
 */
class ForumGroupTest {

    @Test
    void adminMapsToAdministratorsAlways_evenWithoutForum() {
        assertThat(ForumGroup.forRoles(Set.of("ROLE_USER", "ROLE_ADMIN"))).isEqualTo(ForumGroup.ADMINISTRATORS);
    }

    @Test
    void adminMapsToAdministrators_evenWithForumAndMod() {
        assertThat(ForumGroup.forRoles(Set.of("ROLE_ADMIN", "ROLE_MOD", "ROLE_FORUM")))
                .isEqualTo(ForumGroup.ADMINISTRATORS);
    }

    @Test
    void modAndForumMapsToGlobalModerators() {
        assertThat(ForumGroup.forRoles(Set.of("ROLE_USER", "ROLE_MOD", "ROLE_FORUM")))
                .isEqualTo(ForumGroup.GLOBAL_MODERATORS);
    }

    @Test
    void modWithoutForumIsNotAModerator_andHasNoAccess() {
        ForumGroup g = ForumGroup.forRoles(Set.of("ROLE_USER", "ROLE_MOD"));
        assertThat(g).isEqualTo(ForumGroup.NONE);
        assertThat(g.grantsAccess()).isFalse();
    }

    @Test
    void forumAloneMapsToRegistered() {
        assertThat(ForumGroup.forRoles(Set.of("ROLE_USER", "ROLE_FORUM"))).isEqualTo(ForumGroup.REGISTERED);
    }

    @Test
    void noForumRoleAndNotAdminIsNone() {
        ForumGroup g = ForumGroup.forRoles(Set.of("ROLE_USER"));
        assertThat(g).isEqualTo(ForumGroup.NONE);
        assertThat(g.grantsAccess()).isFalse();
    }
}
