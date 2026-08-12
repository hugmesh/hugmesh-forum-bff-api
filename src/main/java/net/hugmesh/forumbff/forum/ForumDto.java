package net.hugmesh.forumbff.forum;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

/**
 * The JSON shapes crossing the {@code /bff/forum/**} HTTP boundary AND the phpBB
 * extension boundary. Plain records ({@code @JsonIgnoreProperties(ignoreUnknown)} so
 * an evolving extension never breaks deserialization). The request bodies carry
 * jakarta validation; the {@code authorSubject} on posts/replies is the Casdoor
 * {@code sub} (owner) and is NEVER accepted from the request body — the service sets
 * it from the JWT so a caller cannot author under another user.
 */
public final class ForumDto {

    private ForumDto() {}

    /** A forum category (phpBB forum). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Category(long id, String name, String description, int topicCount) {}

    /** A topic (phpBB topic) within a category. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Topic(long id, long categoryId, String title, String authorSubject,
                        int replyCount, Instant createdAt) {}

    /** A reply (phpBB post) within a topic. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Reply(long id, long topicId, String authorSubject, String body, Instant createdAt) {}

    /** The phpBB user record resolved/created by the extension, keyed by Casdoor sub. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ForumUser(String casdoorSubject, long phpbbUserId, String group) {}

    /** Live content counts read from the extension {@code /stats} (resilience4j fallback to empty). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Stats(long topics, long posts, long activeUsers, long moderationQueueDepth, String source) {
        /** The typed degraded/empty fallback (breaker-open / phpbb.enabled=false / error). */
        public static Stats degraded() {
            return new Stats(0, 0, 0, 0, "degraded");
        }
    }

    // ── request bodies ─────────────────────────────────────────────────

    /** {@code POST /bff/forum/topics}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateTopic(
            long categoryId,
            @NotBlank(message = "title is required") @Size(max = 255, message = "title is too long") String title,
            @NotBlank(message = "body is required") @Size(max = 64000, message = "body is too long") String body) {}

    /** {@code POST /bff/forum/topics/{id}/replies}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateReply(
            @NotBlank(message = "body is required") @Size(max = 64000, message = "body is too long") String body) {}

    /** {@code PUT /bff/forum/posts/{id}}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record EditPost(
            @NotBlank(message = "body is required") @Size(max = 64000, message = "body is too long") String body) {}

    /** A moderation action target ({@code /bff/forum/moderation/**}): hide/lock/delete. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ModerationAction(@NotBlank String action, String reason) {}

    /** The declarative group-set the extension's {@code setUserGroups} converges to. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GroupAssignment(String casdoorSubject, ForumGroup group, List<String> roles, Instant lastSynced) {

        /** Returns a defensive copy so callers cannot mutate the internal roles list. */
        @Override
        public List<String> roles() {
            return roles == null ? List.of() : List.copyOf(roles);
        }
    }

    /**
     * {@code POST /bff/forum/admin/categories} — create a forum category (phpBB forum).
     * The admin-bff console sends {@code {name, description?, parentId?}}; forwarded to the
     * extension's {@code /admin/categories}. {@code name} is required + length-bounded.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateCategory(
            @NotBlank(message = "name is required") @Size(max = 255, message = "name is too long") String name,
            @Size(max = 4000, message = "description is too long") String description,
            Long parentId) {}

    /**
     * One row of the ADMIN moderation queue (a pending/flagged post awaiting
     * approve/reject), read from the extension {@code /admin/moderation-queue}. An
     * evolving extension may add fields ({@code @JsonIgnoreProperties}).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record QueueItem(String id, long topicId, String authorSubject, String excerpt,
                            String state, Instant createdAt) {}

    /**
     * {@code POST /bff/forum/admin/users/{subject}/ban} body — the admin-bff console sends
     * {@code {reason}} as JSON. Optional; the legacy {@code ?reason=} query param still
     * works (the controller prefers the body when present).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BanBody(@Size(max = 1000, message = "reason is too long") String reason) {}

    /**
     * {@code POST /bff/forum/admin/users/{subject}/groups} body — the admin-bff console
     * sends {@code {group}} (a {@link ForumGroup} name). Required + bounded; the controller
     * validates the value against {@link ForumGroup}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GroupBody(
            @NotBlank(message = "group is required") @Size(max = 64, message = "group is too long") String group) {}

    /**
     * {@code POST /bff/forum/admin/styles} and {@code .../extensions} body — the admin-bff
     * console sends {@code {name}} as JSON. The legacy {@code ?name=} query param still
     * works (the controller prefers the body when present).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record InstallBody(
            @NotBlank(message = "name is required") @Size(max = 255, message = "name is too long") String name) {}
}
