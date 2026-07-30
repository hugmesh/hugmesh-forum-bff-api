package systems.hugmesh.forumbff.forum;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of the {@code forum_vn_profile} table (Liquibase {@code 005}) — the
 * visual-novel reading-mode presentation profile for one user, keyed by the IMMUTABLE
 * Casdoor {@code sub} (the same natural-PK decision as {@code forum_user_role},
 * changelog {@code 001} — NOT localpart: two identity providers can yield the same
 * localpart, so {@code sub} is the only collision-safe key).
 *
 * <p>The {@code domain} follows changelog {@code 003} exactly: the brand/tenant the
 * profile belongs to, stamped SERVER-SIDE from the subject's validated-issuer brand
 * (NEVER a request field). The {@code casdoor_subject} PK stays globally-unique;
 * domain is an ADDITIONAL read predicate, never the key. SUPERADMIN is unscoped.
 *
 * <p>The presentation fields are server-validated at the API layer (see
 * {@link VnProfileDto.UpdateVnProfile}): {@code voiceboxStyle} against the
 * {@code [classic|glass|retro|neon|paper]} allowlist, {@code voiceboxAccent} as a
 * {@code #rrggbb} hex, {@code stickerSlug} as a bounded slug, {@code voiceStyle}
 * against {@code [warm|bright|deep|soft|robot]}, and {@code characterImgRef} to a
 * strict same-origin {@code /bff/user/...} path allowlist — it is rendered as an
 * {@code <img src>}, so nothing outside the allowlist ever reaches the row.
 *
 * @param casdoorSubject  the immutable Casdoor {@code sub} — PRIMARY KEY / UNIQUE
 * @param stickerSlug     the sticker shown beside the user's lines (nullable)
 * @param characterImgRef the same-origin {@code /bff/user/...} character image path (nullable)
 * @param voiceboxStyle   the voicebox (dialogue-box) style — one of the server allowlist; never null
 * @param voiceboxAccent  the {@code #rrggbb} voicebox accent colour (nullable)
 * @param voiceStyle      the synthesized voice style — one of the server allowlist (nullable)
 * @param updatedAt       the timestamp of the last profile write
 * @param domain          the brand/tenant the profile belongs to (server-derived; {@code default} single-tenant)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Table("forum_vn_profile")
public record ForumVnProfile(
        @Id @Column("casdoor_subject") String casdoorSubject,
        @Column("sticker_slug") String stickerSlug,
        @Column("character_img_ref") String characterImgRef,
        @Column("voicebox_style") String voiceboxStyle,
        @Column("voicebox_accent") String voiceboxAccent,
        @Column("voice_style") String voiceStyle,
        @Column("updated_at") Instant updatedAt,
        @Column("domain") String domain) {
}
