package net.hugmesh.forumbff.forum;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ForumActionVerb} contract: the enum is a CODE-SIDE lens over the closed
 * {@code forum_action.action} vocabulary, and every constant's {@link
 * ForumActionVerb#token()} is BYTE-IDENTICAL to the prior inline {@code admin.forum.*}
 * String literal the service/controller emitted into the audit row. These tests pin
 * that equivalence so the enum can never silently drift a stored token — the audit
 * trail (and the HTTP/repository tests that assert on the exact {@code action} string)
 * keep reading the same values. Mirrors the hugmesh-federation-api {@code
 * ScopeKindTest} exemplar.
 */
class ForumActionVerbTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void token_isTheExactLowercaseDottedWireToken() {
        // The stored/transmitted token is the lowercase-dotted form, NOT the Java constant name.
        assertThat(ForumActionVerb.USER_BAN.token()).isEqualTo("admin.forum.user.ban");
        assertThat(ForumActionVerb.USER_UNBAN.token()).isEqualTo("admin.forum.user.unban");
        assertThat(ForumActionVerb.USER_SYNC_GROUPS.token()).isEqualTo("admin.forum.user.sync-groups");
        assertThat(ForumActionVerb.USER_ASSIGN_GROUP.token()).isEqualTo("admin.forum.user.assign-group");
        assertThat(ForumActionVerb.CATEGORY_CREATE.token()).isEqualTo("admin.forum.category.create");
        assertThat(ForumActionVerb.MODERATION_APPROVE.token()).isEqualTo("admin.forum.moderation.approve");
        assertThat(ForumActionVerb.MODERATION_REJECT.token()).isEqualTo("admin.forum.moderation.reject");
        assertThat(ForumActionVerb.STYLE_INSTALL.token()).isEqualTo("admin.forum.style.install");
        assertThat(ForumActionVerb.EXTENSION_INSTALL.token()).isEqualTo("admin.forum.extension.install");
    }

    @Test
    void values_areExactlyTheClosedSet() {
        // The full closed set of audited forum action verbs, in declaration order.
        List<String> tokens = Arrays.stream(ForumActionVerb.values()).map(ForumActionVerb::token).toList();
        assertThat(tokens).containsExactly(
                "admin.forum.user.ban",
                "admin.forum.user.unban",
                "admin.forum.user.sync-groups",
                "admin.forum.user.assign-group",
                "admin.forum.category.create",
                "admin.forum.moderation.approve",
                "admin.forum.moderation.reject",
                "admin.forum.style.install",
                "admin.forum.extension.install");
    }

    @Test
    void everyTokenIsTheAdminForumNamespace() {
        // Defensive: no verb may ever leave the admin.forum.* namespace.
        for (ForumActionVerb v : ForumActionVerb.values()) {
            assertThat(v.token()).startsWith("admin.forum.");
        }
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (ForumActionVerb v : ForumActionVerb.values()) {
            // token() -> fromWire() returns the SAME constant (round-trip identity).
            assertThat(ForumActionVerb.fromWire(v.token())).isEqualTo(v);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        // A null / unknown / wrong-case token maps to null — the audit trail can carry rows
        // from other code paths, so an unrecognised verb must never throw.
        assertThat(ForumActionVerb.fromWire(null)).isNull();
        assertThat(ForumActionVerb.fromWire("")).isNull();
        assertThat(ForumActionVerb.fromWire("admin.forum.user.delete")).isNull();
        assertThat(ForumActionVerb.fromWire("ADMIN.FORUM.USER.BAN")).isNull(); // case-sensitive
        assertThat(ForumActionVerb.fromWire("user.ban")).isNull();
    }

    @Test
    void json_serializesToLowercaseDottedToken() throws Exception {
        // @JsonValue => the enum serializes to its wire token, never "USER_BAN".
        assertThat(MAPPER.writeValueAsString(ForumActionVerb.USER_BAN)).isEqualTo("\"admin.forum.user.ban\"");
        assertThat(MAPPER.writeValueAsString(ForumActionVerb.STYLE_INSTALL)).isEqualTo("\"admin.forum.style.install\"");
    }

    @Test
    void json_deserializesFromLowercaseDottedToken() throws Exception {
        // @JsonCreator(fromWire) => the wire token parses back to the constant.
        assertThat(MAPPER.readValue("\"admin.forum.user.ban\"", ForumActionVerb.class))
                .isEqualTo(ForumActionVerb.USER_BAN);
        assertThat(MAPPER.readValue("\"admin.forum.moderation.reject\"", ForumActionVerb.class))
                .isEqualTo(ForumActionVerb.MODERATION_REJECT);
    }

    @Test
    void json_unknownTokenDeserializesToNull_neverThrows() throws Exception {
        // An unrecognised token is tolerated (null), mirroring the read-path leniency.
        assertThat(MAPPER.readValue("\"nope\"", ForumActionVerb.class)).isNull();
    }
}
