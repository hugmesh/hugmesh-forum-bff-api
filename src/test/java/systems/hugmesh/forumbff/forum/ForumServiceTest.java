package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.forumbff.external.BlockOutcome;
import systems.hugmesh.forumbff.external.PhpbbAdminClient;
import systems.hugmesh.forumbff.phpbb.PhpbbApiClient;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.forumbff.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The cross-cutting wrap rules: ownership (owner==jwt.sub||ADMIN), the moderator gate
 * (ADMIN OR MOD-AND-FORUM), the ban congruence ALWAYS auditing to forum_action
 * regardless of the stubbed outcome, and the acts-as-user binding keyed by Casdoor sub
 * (NOT localpart) — two subjects sharing a localpart resolve to two distinct phpBB users.
 *
 * <p>These are USER-SITUATIONAL service rules; the principals here use a non-JWT
 * {@link Authentication} stub, so {@link ForumService} falls back to the platform
 * {@code default} domain (the {@link PrincipalDomain} is wired with a single-issuer
 * registry). The DOMAIN-scope cross-user behaviour is exercised in the repository
 * slice tests + {@code ForumDomainScopeTest}.
 */
class ForumServiceTest {

    private final PhpbbApiClient phpbb = mock(PhpbbApiClient.class);
    private final PhpbbAdminClient phpbbAdmin = mock(PhpbbAdminClient.class);
    private final ForumUserRoleRepository userRoles = mock(ForumUserRoleRepository.class);
    private final ForumActionRepository audit = mock(ForumActionRepository.class);
    private final PrincipalDomain principalDomain = new PrincipalDomain(new DomainRegistry("", ""));
    private final ForumService service =
            new ForumService(phpbb, phpbbAdmin, userRoles, audit, principalDomain);

    private static Authentication auth(String subject, String... authorities) {
        UsernamePasswordAuthenticationToken t = new UsernamePasswordAuthenticationToken(
                subject, "n/a", AuthorityUtils.createAuthorityList(authorities));
        return t;
    }

    // ── ownership ──────────────────────────────────────────────────────
    @Test
    void ownerPasses() {
        service.assertOwnerOrAdmin("sub-1", auth("sub-1", "ROLE_FORUM"));
    }

    @Test
    void adminPassesEvenIfNotOwner() {
        service.assertOwnerOrAdmin("sub-1", auth("sub-2", "ROLE_ADMIN"));
    }

    @Test
    void nonOwnerNonAdmin_forbidden() {
        assertThatThrownBy(() -> service.assertOwnerOrAdmin("sub-1", auth("sub-2", "ROLE_FORUM")))
                .isInstanceOf(ApiException.class);
    }

    // ── isOwnerOrAdmin predicate (the reactive fail-closed gate's basis) ─
    @Test
    // ALLOW: owner subject matches the post's authorSubject.
    void isOwnerOrAdmin_trueForOwner() {
        assertThat(service.isOwnerOrAdmin("sub-1", auth("sub-1", "ROLE_FORUM"))).isTrue();
    }

    @Test
    // ALLOW: ADMIN override even when not the owner.
    void isOwnerOrAdmin_trueForAdminEvenIfNotOwner() {
        assertThat(service.isOwnerOrAdmin("sub-1", auth("sub-2", "ROLE_ADMIN"))).isTrue();
    }

    @Test
    // CROSS-USER DENY: a different subject is not the owner and not admin.
    void isOwnerOrAdmin_falseForOtherUser() {
        assertThat(service.isOwnerOrAdmin("sub-1", auth("sub-2", "ROLE_FORUM"))).isFalse();
    }

    @Test
    // FAIL-CLOSED: a null author (unresolvable post) never matches a real caller subject.
    void isOwnerOrAdmin_falseForNullAuthor() {
        assertThat(service.isOwnerOrAdmin(null, auth("sub-1", "ROLE_FORUM"))).isFalse();
    }

    // ── moderator gate ─────────────────────────────────────────────────
    @Test
    void modAndForum_isModerator() {
        service.assertModerator(auth("sub-1", "ROLE_MOD", "ROLE_FORUM"));
    }

    @Test
    void admin_isModerator() {
        service.assertModerator(auth("sub-1", "ROLE_ADMIN"));
    }

    @Test
    // CASCADE: SUPERADMIN ≥ ADMIN ≥ MOD — a SUPERADMIN (no raw ROLE_ADMIN, no MOD/FORUM)
    // satisfies the moderator gate, consistent with the /admin surface it also reaches.
    void superadmin_isModerator() {
        service.assertModerator(auth("root", "ROLE_USER", "ROLE_SUPERADMIN"));
    }

    @Test
    // CASCADE (owner override): a SUPERADMIN outranks the owner check, like an ADMIN.
    void superadmin_isOwnerOrAdmin_trueEvenIfNotOwner() {
        assertThat(service.isOwnerOrAdmin("sub-1", auth("root", "ROLE_USER", "ROLE_SUPERADMIN"))).isTrue();
    }

    @Test
    void modWithoutForum_notModerator_forbidden() {
        assertThatThrownBy(() -> service.assertModerator(auth("sub-1", "ROLE_MOD")))
                .isInstanceOf(ApiException.class);
    }

    @Test
    // NOT broadened beyond the cascade: a plain USER is still denied moderation.
    void plainUser_notModerator_forbidden() {
        assertThatThrownBy(() -> service.assertModerator(auth("sub-1", "ROLE_USER")))
                .isInstanceOf(ApiException.class);
    }

    // ── ban congruence always audits ───────────────────────────────────
    @Test
    void ban_stubbed_stillAuditsForumAction() {
        when(phpbbAdmin.suspendUser(eq("sub-9"), any())).thenReturn(Mono.just(BlockOutcome.STUBBED));
        when(audit.record(anyString(), eq("admin.forum.user.ban"), eq("sub-9"), eq("stubbed"), any(), anyString()))
                .thenReturn(Mono.just(new ForumAction("a", "admin", "admin.forum.user.ban", "sub-9",
                        "stubbed", "abuse", java.time.Instant.now(), "default")));
        StepVerifier.create(service.ban("sub-9", "abuse", auth("admin", "ROLE_ADMIN")))
                .assertNext(o -> org.assertj.core.api.Assertions.assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
    }

    // ── acts-as-user: bound by Casdoor sub, NOT localpart ──────────────
    @Test
    void twoSubjectsSharingLocalpart_resolveDistinctPhpbbUsers() {
        when(phpbb.ensureUser("sub-A")).thenReturn(Mono.just(new ForumDto.ForumUser("sub-A", 100L, "REGISTERED")));
        when(phpbb.ensureUser("sub-B")).thenReturn(Mono.just(new ForumDto.ForumUser("sub-B", 200L, "REGISTERED")));
        when(userRoles.upsert(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ForumUserRole("x", 0L, "REGISTERED", java.time.Instant.now(), "default")));

        // Same localpart "alice" but two different Casdoor subjects -> two distinct phpBB user ids.
        StepVerifier.create(service.ensureUser(auth("sub-A", "ROLE_FORUM")))
                .assertNext(u -> org.assertj.core.api.Assertions.assertThat(u.phpbbUserId()).isEqualTo(100L))
                .verifyComplete();
        StepVerifier.create(service.ensureUser(auth("sub-B", "ROLE_FORUM")))
                .assertNext(u -> org.assertj.core.api.Assertions.assertThat(u.phpbbUserId()).isEqualTo(200L))
                .verifyComplete();
    }

    // ── audit-trail anti-DoS bound: the limit is ALWAYS clamped server-side ──

    /** (a) DEFAULT CAP: no {@code ?limit=} (null) reads the trail bounded to the default
     *  cap, NOT the whole table — the bounded {@code list(domain, limit)} is called with
     *  {@link ForumService#FORUM_AUDIT_DEFAULT_LIMIT}, never the unbounded {@code list}. */
    @Test
    void auditTrail_noLimit_appliesDefaultCap() {
        when(audit.list(anyString(), anyInt())).thenReturn(reactor.core.publisher.Flux.empty());

        service.auditTrail(auth("admin", "ROLE_ADMIN")).collectList().block();

        // non-JWT stub principal -> the platform default domain; default cap applied.
        verify(audit).list(eq(DomainRegistry.DEFAULT_DOMAIN), eq(ForumService.FORUM_AUDIT_DEFAULT_LIMIT));
    }

    /** (b) CLAMP TO MAX: an over-cap requested limit is clamped DOWN to the hard ceiling
     *  server-side — a caller can never widen the scan past {@link
     *  ForumService#FORUM_AUDIT_MAX_LIMIT}. */
    @Test
    void auditTrail_overCapLimit_clampedToMax() {
        when(audit.list(anyString(), anyInt())).thenReturn(reactor.core.publisher.Flux.empty());

        service.auditTrail(auth("admin", "ROLE_ADMIN"), 1_000_000).collectList().block();

        verify(audit).list(eq(DomainRegistry.DEFAULT_DOMAIN), eq(ForumService.FORUM_AUDIT_MAX_LIMIT));
    }

    /** The clamp is pure + fail-closed: null / non-positive -> default; in-range passes
     *  through; over-cap -> max. */
    @Test
    void clampAuditLimit_normalisesAllInputs() {
        assertThat(ForumService.clampAuditLimit(null)).isEqualTo(ForumService.FORUM_AUDIT_DEFAULT_LIMIT);
        assertThat(ForumService.clampAuditLimit(0)).isEqualTo(ForumService.FORUM_AUDIT_DEFAULT_LIMIT);
        assertThat(ForumService.clampAuditLimit(-5)).isEqualTo(ForumService.FORUM_AUDIT_DEFAULT_LIMIT);
        assertThat(ForumService.clampAuditLimit(50)).isEqualTo(50);
        assertThat(ForumService.clampAuditLimit(ForumService.FORUM_AUDIT_MAX_LIMIT + 1))
                .isEqualTo(ForumService.FORUM_AUDIT_MAX_LIMIT);
    }
}
