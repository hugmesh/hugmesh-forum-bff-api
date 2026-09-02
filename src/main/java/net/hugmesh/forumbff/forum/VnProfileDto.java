package net.hugmesh.forumbff.forum;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;

/**
 * The JSON shapes crossing the {@code /bff/forum/vn-profiles/**} HTTP boundary — the
 * visual-novel reading-mode presentation profile. Plain records
 * ({@code @JsonIgnoreProperties(ignoreUnknown)} so an evolving client never breaks
 * deserialization — and so a smuggled {@code "subject"} field in the update body is
 * silently DROPPED: the subject comes ONLY from the JWT). The request bodies carry
 * jakarta validation implementing the pinned contract's server-enforced constraints.
 *
 * <p><b>Why the {@code characterImgRef} allowlist is strict:</b> the value is rendered
 * by the VN reader as an {@code <img src>}. The pattern pins it to a same-origin
 * {@code /bff/user/...} path over a conservative character set (no scheme, no
 * {@code ://}, no query/fragment, no {@code ..} traversal), max 256 chars — so a
 * profile can never point a reader's browser at an attacker-controlled origin.
 *
 * <p><b>What actually serves those paths (issue #3):</b> hugmesh-user-bff-api. A VN
 * character avatar is {@code GET /bff/user/character/avatar/&#123;ref&#125;/body}
 * (opaque per-owner handle; its owner reads the handle from
 * {@code GET /bff/user/character/avatar}), and a sticker is
 * {@code GET /bff/user/character/stickers/&#123;slug&#125;/body}. Both serve to other
 * users in the same brand so a sprite renders inside their posts. This BFF stays
 * agnostic about whether a stored path resolves, but the allowlist must not be
 * narrowed past those two spellings — {@link #CANONICAL_AVATAR_REF_SHAPE} /
 * {@link #CANONICAL_STICKER_REF_SHAPE} pin them.
 */
public final class VnProfileDto {

    private VnProfileDto() {}

    // ── server-enforced allowlists (the pinned contract; clients mirror) ─

    /** The voicebox (dialogue-box) style allowlist. */
    public static final String VOICEBOX_STYLES = "classic|glass|retro|neon|paper";

    /** The synthesized voice style allowlist. */
    public static final String VOICE_STYLES = "warm|bright|deep|soft|robot";

    /** Lowercase {@code #rrggbb} hex — the voicebox accent colour. */
    public static final String HEX_COLOR = "^#[0-9a-f]{6}$";

    /** Bounded lowercase slug — the sticker identifier. */
    public static final String STICKER_SLUG = "^[a-z0-9_-]{1,64}$";

    /** The required same-origin prefix for {@code characterImgRef} (rendered as an
     *  {@code <img src>} — see the class doc). */
    public static final String CHARACTER_IMG_PREFIX = "/bff/user/";

    /** Strict same-origin {@code /bff/user/...} path allowlist: conservative path
     *  characters only (no scheme/authority/query/fragment possible), no {@code ..}
     *  traversal, ≤256 chars total (10-char prefix + ≤246). */
    //
    // This BFF validates the SHAPE and never dereferences it — deliberately. The two
    // routes that actually serve those paths live in hugmesh-user-bff-api:
    //   * a VN character avatar — GET /bff/user/character/avatar/{ref}/body, where
    //     {ref} is the opaque per-owner handle its owner reads from
    //     GET /bff/user/character/avatar (see CharacterAvatarController);
    //   * a character sticker  — GET /bff/user/character/stickers/{slug}/body.
    // Both are readable by other users in the same brand, which is what makes a
    // sprite render inside someone else's post. Issue #3 was that hugmesh-forum-ui
    // stored the BARE path "/bff/user/character/avatar": it named no owner, nothing
    // served it, and every avatar-mode profile rendered a broken image. The UI now
    // stores the resolved body URL, so DO NOT tighten this charset in a way that
    // would stop a real serve URL validating — {@link #CANONICAL_AVATAR_REF_SHAPE}
    // and VnProfileControllerTest pin that cross-repo contract.
    public static final String CHARACTER_IMG_REF =
            "^/bff/user/(?!.*\\.\\.)[A-Za-z0-9._/-]{1,246}$";

    /** The exact shape hugmesh-user-bff-api's character-avatar serve route produces
     *  and hugmesh-forum-ui stores as a {@code characterImgRef}
     *  ({@code /bff/user/character/avatar/<uuid>/body}). Held here as the pinned
     *  cross-repo contract: {@link #CHARACTER_IMG_REF} MUST keep accepting it. */
    public static final String CANONICAL_AVATAR_REF_SHAPE =
            "^/bff/user/character/avatar/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            + "[0-9a-f]{4}-[0-9a-f]{12}/body$";

    /** The exact shape hugmesh-user-bff-api's sticker serve route produces
     *  ({@code /bff/user/character/stickers/<slug>/body}) — the sibling media path,
     *  pinned for the same reason as {@link #CANONICAL_AVATAR_REF_SHAPE}. */
    public static final String CANONICAL_STICKER_REF_SHAPE =
            "^/bff/user/character/stickers/[a-z0-9_-]{1,64}/body$";

    /** The maximum number of subjects one lookup may resolve. */
    public static final int LOOKUP_MAX_SUBJECTS = 50;

    // ── responses ────────────────────────────────────────────────────────

    /**
     * The caller's own VN profile ({@code GET/PUT /bff/forum/vn-profiles/me}).
     * {@code subject} is the Casdoor {@code sub} the profile belongs to — always the
     * JWT subject, echoed for the client's benefit. {@code GET /me} NEVER 404s: when
     * no row exists the service synthesizes {@link #defaults}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record VnProfile(String subject, String stickerSlug, String characterImgRef,
                            String voiceboxStyle, String voiceboxAccent, String voiceStyle) {

        /** The synthesized no-row defaults the {@code GET /me} contract promises:
         *  everything null except {@code voiceboxStyle: "classic"}. */
        public static VnProfile defaults(String subject) {
            return new VnProfile(subject, null, null, "classic", null, null);
        }
    }

    /** One subject's profile inside the lookup response map (the subject is the map
     *  KEY, so it is not repeated here). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record VnProfileView(String stickerSlug, String characterImgRef,
                                String voiceboxStyle, String voiceboxAccent, String voiceStyle) {}

    /** {@code POST /bff/forum/vn-profiles/lookup} response — subject → profile;
     *  subjects with no row are simply ABSENT (never a 404, never a null value). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record VnLookupResponse(Map<String, VnProfileView> profiles) {

        /** Returns a defensive copy so callers cannot mutate the internal map. */
        @Override
        public Map<String, VnProfileView> profiles() {
            return profiles == null ? Map.of() : Map.copyOf(profiles);
        }
    }

    // ── request bodies ───────────────────────────────────────────────────

    /**
     * {@code PUT /bff/forum/vn-profiles/me}. Carries NO subject field — the subject
     * comes ONLY from the JWT ({@code Authentication.getName()}); a smuggled
     * {@code "subject"} JSON field is dropped by {@code ignoreUnknown}. All optional
     * fields accept {@code null} (which clears the stored value); {@code voiceboxStyle}
     * is required.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UpdateVnProfile(
            @Pattern(regexp = STICKER_SLUG,
                    message = "stickerSlug must be a 1-64 char lowercase slug of [a-z0-9_-]")
            String stickerSlug,
            @Size(max = 256, message = "characterImgRef is too long")
            @Pattern(regexp = CHARACTER_IMG_REF,
                    message = "characterImgRef must be a same-origin /bff/user/ path")
            String characterImgRef,
            @NotBlank(message = "voiceboxStyle is required")
            @Pattern(regexp = "^(" + VOICEBOX_STYLES + ")$",
                    message = "voiceboxStyle must be one of [" + VOICEBOX_STYLES + "]")
            String voiceboxStyle,
            @Pattern(regexp = HEX_COLOR,
                    message = "voiceboxAccent must be a lowercase #rrggbb hex colour")
            String voiceboxAccent,
            @Pattern(regexp = "^(" + VOICE_STYLES + ")$",
                    message = "voiceStyle must be one of [" + VOICE_STYLES + "]")
            String voiceStyle) {}

    /**
     * {@code POST /bff/forum/vn-profiles/lookup} — the VN reader's batched
     * author-profile resolve. 1..{@value #LOOKUP_MAX_SUBJECTS} subjects (an empty or
     * oversized list is a 400 via bean validation); the service DEDUPS before querying
     * so duplicates cannot widen the scan.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record VnLookupRequest(
            @NotNull(message = "subjects is required")
            @Size(min = 1, max = LOOKUP_MAX_SUBJECTS,
                    message = "subjects must contain between 1 and " + LOOKUP_MAX_SUBJECTS + " entries")
            List<@NotBlank(message = "subject must not be blank")
                 @Size(max = 255, message = "subject is too long") String> subjects) {

        /** Returns a defensive copy so callers cannot mutate the internal list. */
        @Override
        public List<String> subjects() {
            return subjects == null ? List.of() : List.copyOf(subjects);
        }
    }
}
