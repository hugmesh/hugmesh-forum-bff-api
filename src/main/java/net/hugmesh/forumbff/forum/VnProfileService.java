package net.hugmesh.forumbff.forum;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.forumbff.security.PrincipalDomain;

import java.util.ArrayDeque;
import java.util.Deque;
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
 *   <li><b>Owner-blind refs never reach a reader</b> — the two subject-implicit
 *       {@code /bff/user/**} spellings ({@link VnProfileDto#OWNER_BLIND_IMG_REFS}) pass
 *       the charset allowlist but can only ever resolve against the CALLER, so as a post
 *       sprite they are a broken image (the handle endpoint, issue #3's original defect)
 *       or the reader's OWN face on someone else's post (the owner-scoped self-avatar
 *       serve). {@link #renderableImgRef} suppresses BOTH on the reader-facing lookup;
 *       {@link #storableImgRef} additionally refuses to store the self-avatar serve,
 *       which no client writes. The legacy handle ref is deliberately still STORED and
 *       still echoed by {@code GET /me}: it is the signal the owner's editor re-ticks
 *       from, and erasing it is the same loss that rules out a NULLing migration.
 *       Every comparison runs on the CANONICAL path ({@link #wirePath}), because a
 *       browser normalises {@code /a/./b} to {@code /a/b} and a string compare does
 *       not.</li>
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
     * server-side. An UNSTORABLE ref is cleared to {@code null} first
     * ({@link #storableImgRef}) rather than rejected — the write succeeds with the
     * image field empty.
     *
     * @param auth the caller's {@link Authentication} (subject + domain derived from it)
     * @param body the validated {@link VnProfileDto.UpdateVnProfile} request body
     * @return a {@code Mono} emitting the saved profile as stored
     */
    public Mono<VnProfileDto.VnProfile> update(Authentication auth, VnProfileDto.UpdateVnProfile body) {
        String subject = ForumService.subject(auth);   // ONLY the JWT sub — never the body
        String imgRef = storableImgRef(body.characterImgRef());   // self-avatar serve -> cleared
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
     * The path a BROWSER would actually request for {@code ref} — the canonical form the
     * owner-blind rules are compared against.
     *
     * <p>A rule that compares the RAW stored string is not the rule it looks like: a URL
     * parser removes {@code .} / {@code ..} dot-segments (RFC 3986 §5.2.4) and
     * intermediaries collapse empty segments, so
     * {@code /bff/user/profile/avatar/./body} is a different string and the SAME
     * endpoint. Chromium proves it — it deduplicates that {@code <img src>} against a
     * plain {@code /bff/user/profile/avatar/body} and puts the plain path on the wire.
     * {@link VnProfileDto#CHARACTER_IMG_REF} refuses those spellings on the way IN, but
     * rows written before that rule existed are still in the table, so the comparison
     * itself has to canonicalise.
     *
     * <p>Also drops a query/fragment (impossible under the current charset, so this is
     * belt-and-braces against a future widening) and trims trailing slashes.
     *
     * @param ref the stored/incoming reference; never {@code null}
     * @return the canonical absolute path, with no dot, empty or trailing segments
     */
    static String wirePath(String ref) {
        int cut = ref.length();
        for (int i = 0; i < ref.length(); i++) {
            char c = ref.charAt(i);
            if (c == '?' || c == '#') {
                cut = i;
                break;
            }
        }
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : ref.substring(0, cut).split("/", -1)) {
            if (segment.isEmpty() || ".".equals(segment)) {
                continue;                    // empty + "." segments vanish
            }
            if ("..".equals(segment)) {
                segments.pollLast();         // ".." pops (and is a no-op at the root)
                continue;
            }
            segments.addLast(segment);
        }
        return (ref.startsWith("/") ? "/" : "") + String.join("/", segments);
    }

    /**
     * The ref as it may be RENDERED to a READER: {@code null} for an owner-blind
     * spelling ({@link VnProfileDto#OWNER_BLIND_IMG_REFS}), otherwise the value
     * unchanged.
     *
     * <p>Applied to {@code POST /lookup} ONLY, which is the only reader-facing surface —
     * and applied there rather than in the UI because the server is the layer every
     * consumer shares (today hugmesh-forum-ui is the only one, so this is a durability
     * argument, not a fleet of broken clients). It is what repairs the rows written
     * BEFORE this rule existed, without a data migration — and a NULLing migration is
     * deliberately NOT the answer, because it would erase the only signal the owner's
     * editor uses to re-tick "use my avatar" and rewrite the ref to a resolvable one on
     * their next save (hugmesh-forum-ui {@code vn-profile-editor.component.ts}).
     *
     * <p>{@code GET /me} is therefore deliberately NOT filtered: it is the OWNER's own
     * editing surface and must show what is stored. Only {@link #toView}, the
     * reader-facing projection, suppresses.
     *
     * @param ref the stored reference; {@code null} passes through
     * @return the ref, or {@code null} when it is owner-blind
     */
    static String renderableImgRef(String ref) {
        if (ref == null) {
            return null;
        }
        return VnProfileDto.OWNER_BLIND_IMG_REFS.contains(wirePath(ref)) ? null : ref;
    }

    /**
     * The ref as it may be STORED: {@code null} for an UNSTORABLE spelling
     * ({@link VnProfileDto#UNSTORABLE_IMG_REFS}), otherwise the value unchanged.
     *
     * <p>Cleared, not rejected: a 400 would turn "my sprite is wrong" into "my VN
     * profile will not save at all" for edits — voicebox, voice, sticker — that have
     * nothing to do with the image.
     *
     * <p>The set is NARROWER than {@link VnProfileDto#OWNER_BLIND_IMG_REFS} on purpose.
     * See {@link VnProfileDto#UNSTORABLE_IMG_REFS}: clearing the legacy handle ref here
     * would perform, one row at a time, exactly the signal erasure used to rule out a
     * migration — a pre-#14 bundle sends that literal on every save, so its owner's
     * "use my avatar" tick would silently flip off and could never be turned back on.
     * The reader is already protected by {@link #renderableImgRef}.
     *
     * @param ref the incoming reference; {@code null} passes through
     * @return the ref, or {@code null} when it must never be stored
     */
    static String storableImgRef(String ref) {
        if (ref == null) {
            return null;
        }
        return VnProfileDto.UNSTORABLE_IMG_REFS.contains(wirePath(ref)) ? null : ref;
    }

    /** The OWNER's own view — echoed exactly as stored (see {@link #renderableImgRef}
     *  for why a legacy owner-blind ref must survive to this surface). */
    private static VnProfileDto.VnProfile toProfile(ForumVnProfile row) {
        return new VnProfileDto.VnProfile(row.casdoorSubject(), row.stickerSlug(),
                row.characterImgRef(), row.voiceboxStyle(), row.voiceboxAccent(), row.voiceStyle());
    }

    /** A READER's view of another author — an owner-blind ref is suppressed here so it
     *  never reaches an {@code <img src>}; the author's {@code stickerSlug} is untouched,
     *  so the VN reader falls back to their sticker exactly as it does for a cleared ref. */
    private static VnProfileDto.VnProfileView toView(ForumVnProfile row) {
        return new VnProfileDto.VnProfileView(row.stickerSlug(), renderableImgRef(row.characterImgRef()),
                row.voiceboxStyle(), row.voiceboxAccent(), row.voiceStyle());
    }
}
