package systems.hugmesh.forumbff.forum;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * The visual-novel profile surface ({@code /bff/forum/vn-profiles/**}) — the
 * presentation profile the VN reading mode renders per author (sticker, character
 * image, voicebox style/accent, voice style).
 *
 * <p><b>Gating: authenticated, NOT ROLE_FORUM.</b> SecurityConfig gates the whole
 * {@code /bff/forum/**} path {@code .authenticated()}; unlike {@link ForumController}
 * this surface deliberately does NOT re-assert ROLE_FORUM at the method level — the
 * batched {@code /lookup} serves ANY logged-in reader (the VN reader renders other
 * users' posts to principals who may not hold the forum-author role), and {@code /me}
 * is the caller's OWN presentation row. The method-level
 * {@code @PreAuthorize("isAuthenticated()")} re-asserts authentication (defence in
 * depth, matching the repo's method-gate convention) without adding a role floor.
 *
 * <p><b>Subject never from the body.</b> Both {@code /me} verbs key on
 * {@code Authentication.getName()} (the validated JWT {@code sub}) inside
 * {@link VnProfileService}; the update DTO has no subject field and a smuggled one is
 * dropped at deserialization.
 */
@Tag(name = "ForumVnProfile", description = "Visual-novel reading-mode profiles: the caller's own "
        + "sticker/character-image/voicebox presentation (GET/PUT /me, never 404 — defaults are "
        + "synthesized) and the batched author lookup (1..50 subjects). Authenticated; no forum "
        + "role required.")
@RestController
@RequestMapping("/bff/forum/vn-profiles")
@Validated
public class VnProfileController {

    /** Authentication re-asserted at the method level (defence in depth) — deliberately
     *  NOT a role check: any logged-in reader may use this surface. */
    private static final String AUTHENTICATED = "isAuthenticated()";

    private final VnProfileService vnProfiles;

    public VnProfileController(VnProfileService vnProfiles) {
        this.vnProfiles = vnProfiles;
    }

    @Operation(operationId = "getMyVnProfile", summary = "Get the caller's VN profile "
            + "(never 404 — synthesized defaults when none is stored).")
    @PreAuthorize(AUTHENTICATED)
    @GetMapping("/me")
    public Mono<VnProfileDto.VnProfile> me(Authentication auth) {
        return vnProfiles.me(auth);
    }

    @Operation(operationId = "updateMyVnProfile", summary = "Create or update the caller's VN profile "
            + "(subject always from the JWT, never the body).")
    @PreAuthorize(AUTHENTICATED)
    @PutMapping("/me")
    public Mono<VnProfileDto.VnProfile> updateMe(@Valid @RequestBody VnProfileDto.UpdateVnProfile body,
                                                 Authentication auth) {
        return vnProfiles.update(auth, body);
    }

    @Operation(operationId = "lookupVnProfiles", summary = "Batch-resolve VN profiles for up to 50 "
            + "subjects (subjects with no profile are absent from the map).")
    @PreAuthorize(AUTHENTICATED)
    @PostMapping("/lookup")
    public Mono<VnProfileDto.VnLookupResponse> lookup(@Valid @RequestBody VnProfileDto.VnLookupRequest body,
                                                      Authentication auth) {
        return vnProfiles.lookup(auth, body);
    }
}
