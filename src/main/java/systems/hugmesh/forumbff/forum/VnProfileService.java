package systems.hugmesh.forumbff.forum;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.forumbff.security.PrincipalDomain;

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
     * server-side.
     *
     * @param auth the caller's {@link Authentication} (subject + domain derived from it)
     * @param body the validated {@link VnProfileDto.UpdateVnProfile} request body
     * @return a {@code Mono} emitting the saved profile as stored
     */
    public Mono<VnProfileDto.VnProfile> update(Authentication auth, VnProfileDto.UpdateVnProfile body) {
        String subject = ForumService.subject(auth);   // ONLY the JWT sub — never the body
        assertCharacterImgRef(body.characterImgRef()); // defence-in-depth allowlist re-check
        return profiles.upsert(subject, body.stickerSlug(), body.characterImgRef(),
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

    private static VnProfileDto.VnProfile toProfile(ForumVnProfile row) {
        return new VnProfileDto.VnProfile(row.casdoorSubject(), row.stickerSlug(),
                row.characterImgRef(), row.voiceboxStyle(), row.voiceboxAccent(), row.voiceStyle());
    }

    private static VnProfileDto.VnProfileView toView(ForumVnProfile row) {
        return new VnProfileDto.VnProfileView(row.stickerSlug(), row.characterImgRef(),
                row.voiceboxStyle(), row.voiceboxAccent(), row.voiceStyle());
    }
}
