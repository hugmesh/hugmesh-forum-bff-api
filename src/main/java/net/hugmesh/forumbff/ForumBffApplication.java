package net.hugmesh.forumbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Forum BFF — the backend that wraps the headless phpBB forum, paired 1:1 with the
 * (separate) {@code hugmesh-forum-ui} Angular remote served at the path
 * {@code /social/forum}. phpBB is BACKEND-ONLY: it has NO gateway route — the only
 * browser->phpBB path is
 *
 * <pre>browser -> fe-gateway /bff/forum/** -> THIS BFF -> phpBB hugmesh/forum-api extension</pre>
 *
 * and the board front-end / ACP / native login are never routed externally. This BFF
 * wraps phpBB per ROLE + ACTION (defence in depth on top of the gateway route-access):
 *
 * <ul>
 *   <li>{@code /bff/forum/**} — authenticated (the ROLE_FORUM floor is enforced at the
 *       gateway; ownership/role is re-checked here);</li>
 *   <li>{@code /bff/forum/moderation/**} —
 *       {@code @PreAuthorize("hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))")}
 *       (the AND of MOD+FORUM, NOT {@code hasAnyRole('MOD','ADMIN')});</li>
 *   <li>{@code /bff/forum/admin/**} — {@code hasRole('ADMIN')} (the admin-console seam
 *       admin-bff calls; admins reach it via the converter's ROLE_ADMIN — no ROLE_FORUM
 *       needed).</li>
 * </ul>
 *
 * <p>phpBB has NO native REST API: the headless mechanism is the design-chosen thin
 * custom phpBB extension ({@code hugmesh/forum-api}, Symfony controllers + DI-injected
 * phpBB services + {@code JsonResponse}). It is implemented here as a GATED STUB-SEAM
 * ({@code phpbb.enabled} default off, audited, never hard-fail), mirroring the mod-bff
 * {@code MastodonAdminClient} stub-seam. Casdoor->phpBB group mapping: ROLE_ADMIN ->
 * ADMINISTRATORS ALWAYS; ROLE_MOD -> GLOBAL_MODERATORS iff ROLE_FORUM; forum role ->
 * REGISTERED; none -> no access. Removing the forum role suspends/blocks the user in
 * phpBB (gated seam), audited to the OWN {@code forum_action} table.
 */
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@SpringBootApplication
public class ForumBffApplication {
    public static void main(String[] args) {
        SpringApplication.run(ForumBffApplication.class, args);
    }
}
