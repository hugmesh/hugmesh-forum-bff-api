package net.hugmesh.forumbff.forum;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.forumbff.security.PrincipalDomain;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The visual-novel profile domain service — owns the {@code forum_vn_profile}
 * read/write rules behind {@link VnProfileController}:
 *
 * <ul>
 *   <li><b>Subject binding</b> — the profile is keyed by the caller's immutable
 *       Casdoor {@code sub} taken ONLY from the validated JWT
 *       ({@link ForumService#subject}); a subject is NEVER accepted from a request
 *       body, so a caller cannot read-as or write-as another user's {@code /me}.</li>
 *   <li><b>Defaults synthesis</b> — {@code GET /me} NEVER 404s: a subject with no row
 *       gets the synthesized {@link VnProfileDto.VnProfile#defaults} (everything null,
 *       {@code voiceboxStyle: "classic"}). Nothing is written on read.</li>
 *   <li><b>Allowlist re-check (defence in depth)</b> — the {@code characterImgRef}
 *       same-origin {@code /bff/user/} allowlist is enforced by bean validation on the
 *       DTO AND re-checked here ({@link #assertCharacterImgRef}) before the write, the
 *       way {@link ForumService#assertModerator} re-checks the method gate — the value
 *       is rendered as an {@code <img src>}, so it must be impossible to persist an
 *       off-origin reference even if a future caller bypasses the annotated DTO.</li>
 *   <li><b>Owner-blind refs are never stored and never served to a reader</b> — the
 *       two subject-implicit {@code /bff/user/**} spellings
 *       ({@link VnProfileDto#OWNER_BLIND_IMG_REFS}) pass the charset allowlist but can
 *       only ever resolve against the CALLER, so as a post sprite they are a broken
 *       image (the handle endpoint, issue #3's original defect) or the reader's OWN
 *       face on someone else's post (the owner-scoped self-avatar serve).
 *       {@link #resolvableImgRef} clears them on write and suppresses them on the
 *       reader-facing lookup; {@code GET /me} still echoes what is stored so the
 *       owner's editor can repair a legacy row on its next save.</li>
 *   <li><b>Bounded, deduped lookup</b> — the batched author-lookup dedups the
 *       requested subjects (bean validation already caps the raw list at
 *       {@value VnProfileDto#LOOKUP_MAX_SUBJECTS}) and returns ONLY subjects that have
 *       a row — absent subjects are absent keys, never nulls, so the response leaks no
 *       existence signal beyond the profile data itself.</li>
 *   <li><b>Domain-scope</b> — rows are per-brand exactly like {@code forum_user_role}:
 *       the caller's {@code domain} is derived SERVER-SIDE from the validated-issuer
 *       brand ({@link PrincipalDomain}) and stamps/scopes every read + write;
 *       SUPERADMIN is unscoped. NEVER a request field.</li>
 * </ul>
 *
 * @see ForumVnProfileRepository
 * @see VnProfileDto
 * @see PrincipalDomain
 */
@Service
public class VnProfileService {

    private final ForumVnProfileRepository profiles;
    private final PrincipalDomain principalDomain;

    public VnProfileService(ForumVnProfileRepository profiles, PrincipalDomain principalDomain) {
        this.profiles = profiles;
        this.principalDomain = principalDomain;
    }

    /**
     * The caller's effective domain-scope, derived SERVER-SIDE from the validated JWT
     * issuer ({@link PrincipalDomain}) — the same resolution as
     * {@code ForumService.scopeOf}: {@code null} for SUPERADMIN (cross-domain bypass),
     * else the concrete brand ({@code __deny__} for an unresolvable non-SUPERADMIN
     * issuer — fail-closed). Non-JWT principals (test stubs) fall back to the platform
     * {@code default} domain. NEVER read from a request field.
     */
    private String scopeOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return principalDomain.forScope(jwt);
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }

    /**
     * The caller's own VN profile ({@code GET /me}). NEVER empty and never a 404: a
     * subject with no {@code forum_vn_profile} row gets the synthesized defaults
     * ({@code stickerSlug/characterImgRef/voiceboxAccent/voiceStyle} null,
     * {@code voiceboxStyle "classic"}) — nothing is written on read.
     *
     * @param auth the caller's {@link Authentication} (subject + domain derived from it)
     * @return a {@code Mono} emitting the stored profile, or the synthesized defaults
     */
    public Mono<VnProfileDto.VnProfile> me(Authentication auth) {
        String subject = ForumService.subject(auth);
        return profiles.findBySubject(subject, scopeOf(auth))
                .map(VnProfileService::toProfile)
                .defaultIfEmpty(VnProfileDto.VnProfile.defaults(subject));
    }

    /**
     * Upsert the caller's own VN profile ({@code PUT /me}). The subject is ALWAYS the
     * JWT {@code sub} ({@link ForumService#subject}) — the body carries no subject
     * field and a smuggled one is dropped at deserialization. The
     * {@code characterImgRef} allowlist is re-checked here (defence in depth on top of
     * the DTO bean validation) before anything is written; the brand domain is stamped
     * server-side. An OWNER-BLIND ref is cleared to {@code null} first
     * ({@link #resolvableImgRef}) rather than rejected — the write succeeds with the
     * image field empty.
     *
     * @param auth the caller's {@link Authentication} (subject + domain derived from it)
     * @param body the validated {@link VnProfileDto.UpdateVnProfile} request body
     * @return a {@code Mono} emitting the saved profile as stored
     */
    public Mono<VnProfileDto.VnProfile> update(Authentication auth, VnProfileDto.UpdateVnProfile body) {
        String subject = ForumService.subject(auth);   // ONLY the JWT sub — never the body
        String imgRef = resolvableImgRef(body.characterImgRef()); // owner-blind -> cleared
        assertCharacterImgRef(imgRef);                 // defence-in-depth allowlist re-check
        return profiles.upsert(subject, body.stickerSlug(), imgRef,
                        body.voiceboxStyle(), body.voiceboxAccent(), body.voiceStyle(), scopeOf(auth))
                .map(VnProfileService::toProfile);
    }

    /**
     * Batched author-profile lookup ({@code POST /lookup}) — the VN reader resolves
     * the presentation for every author on a page in ONE call. The raw list is capped
     * at {@value VnProfileDto#LOOKUP_MAX_SUBJECTS} by bean validation; here it is
     * DEDUPED (order-preserving) so duplicates cannot widen the scan. Subjects with no
     * row are simply ABSENT from the returned map.
     *
     * @param auth the caller's {@link Authentication} (domain-scope derived from it)
     * @param body the validated {@link VnProfileDto.VnLookupRequest} (1..50 subjects)
     * @return a {@code Mono} emitting the subject → profile map (missing subjects absent)
     */
    public Mono<VnProfileDto.VnLookupResponse> lookup(Authentication auth, VnProfileDto.VnLookupRequest body) {
        Set<String> deduped = new LinkedHashSet<>(body.subjects());
        return profiles.findBySubjects(deduped, scopeOf(auth))
                .collectMap(ForumVnProfile::casdoorSubject, VnProfileService::toView)
                .map(VnProfileDto.VnLookupResponse::new);
    }

    /**
     * Service-layer re-check of the {@code characterImgRef} same-origin allowlist
     * (defence in depth on top of the DTO {@code @Pattern}): the value is rendered as
     * an {@code <img src>}, so it must start with {@value VnProfileDto#CHARACTER_IMG_PREFIX},
     * stay ≤256 chars, and match the strict path pattern (no scheme/authority, no
     * {@code ..} traversal). {@code null} (clear the image) is allowed.
     *
     * @param ref the candidate reference; {@code null} passes (clears the field)
     * @throws ApiException with HTTP 400 when the reference is outside the allowlist
     */
    static void assertCharacterImgRef(String ref) {
        if (ref == null) return;
        if (ref.length() > 256
                || !ref.startsWith(VnProfileDto.CHARACTER_IMG_PREFIX)
                || !ref.matches(VnProfileDto.CHARACTER_IMG_REF)) {
            throw ApiException.badRequest("characterImgRef must be a same-origin /bff/user/ path");
        }
    }

    /**
     * The ref as it may be RENDERED: {@code null} for an owner-blind spelling
     * ({@link VnProfileDto#OWNER_BLIND_IMG_REFS}), otherwise the value unchanged.
     *
     * <p>Applied at BOTH ends, for two different reasons:
     * <ul>
     *   <li>on {@code PUT /me}, so an owner-blind ref is never STORED again — the write
     *       still succeeds (the field simply clears). A 400 was the other option and is
     *       the wrong one: the only client that ever sent this literal is a
     *       pre-hugmesh-forum-ui#14 bundle, which sends it on EVERY save, so rejecting
     *       would turn "my sprite is broken" into "my VN profile will not save at all"
     *       for edits — voicebox, voice, sticker — that have nothing to do with it;</li>
     *   <li>on {@code POST /lookup}, so the rows written BEFORE this rule existed stop
     *       reaching readers. That is what makes the repair complete without a data
     *       migration — and a migration is deliberately NOT the answer here: NULLing
     *       those rows would erase the only signal the owner's editor uses to re-tick
     *       "use my avatar" and rewrite the ref to a resolvable one on their next save
     *       (hugmesh-forum-ui {@code vn-profile-editor.component.ts}).</li>
     * </ul>
     *
     * <p>{@code GET /me} is therefore deliberately NOT filtered: it is the OWNER's own
     * editing surface and must show what is stored. Only {@link #toView}, the
     * reader-facing projection, suppresses.
     *
     * @param ref the stored/incoming reference; {@code null} passes through
     * @return the ref, or {@code null} when it is owner-blind
     */
    static String resolvableImgRef(String ref) {
        if (ref == null) {
            return null;
        }
        String normalized = ref.endsWith("/") ? ref.replaceAll("/+$", "") : ref;
        return VnProfileDto.OWNER_BLIND_IMG_REFS.contains(normalized) ? null : ref;
    }

    /** The OWNER's own view — echoed exactly as stored (see {@link #resolvableImgRef}
     *  for why a legacy owner-blind ref must survive to this surface). */
    private static VnProfileDto.VnProfile toProfile(ForumVnProfile row) {
        return new VnProfileDto.VnProfile(row.casdoorSubject(), row.stickerSlug(),
                row.characterImgRef(), row.voiceboxStyle(), row.voiceboxAccent(), row.voiceStyle());
    }

    /** A READER's view of another author — an owner-blind ref is suppressed here so it
     *  never reaches an {@code <img src>}; the author's {@code stickerSlug} is untouched,
     *  so the VN reader falls back to their sticker exactly as it does for a cleared ref. */
    private static VnProfileDto.VnProfileView toView(ForumVnProfile row) {
        return new VnProfileDto.VnProfileView(row.stickerSlug(), resolvableImgRef(row.characterImgRef()),
                row.voiceboxStyle(), row.voiceboxAccent(), row.voiceStyle());
    }
}
