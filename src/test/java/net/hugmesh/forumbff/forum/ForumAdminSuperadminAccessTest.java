package net.hugmesh.forumbff.forum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.config.SecurityConfig;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;
import net.hugmesh.forumbff.web.ApiExceptionHandler;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The cross-domain SUPERADMIN super-role reaching the ADMIN-gated forum-admin seam via
 * the SecurityConfig RoleHierarchy ({@code ROLE_SUPERADMIN > ROLE_ADMIN}). Delineated:
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — SUPERADMIN (no explicit ROLE_ADMIN) is ALLOWED
 *       onto {@code /bff/forum/admin/**} (the hierarchy edge), like an admin.</li>
 *   <li><b>CROSS-USER</b> — a plain ROLE_USER and a ROLE_FORUM user are both DENIED
 *       the admin seam (the isolation invariant: only ADMIN/SUPERADMIN reach it).</li>
 * </ul>
 */
@WebFluxTest(controllers = ForumAdminController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class ForumAdminSuperadminAccessTest {

    // Spring Security 7: mockJwt()'s SecurityContext is only honoured when the
    // springSecurity() configurer's MutatorFilter is in the chain. The @WebFluxTest
    // slice's auto-configured WebTestClient lacks it (the mutator is dropped -> 401),
    // so build the client from the ApplicationContext with .apply(springSecurity()).
    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean PhpbbApiClient phpbb;
    @MockitoBean ForumService forum;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient as(String... authorities) {
        SimpleGrantedAuthority[] granted = new SimpleGrantedAuthority[authorities.length];
        for (int i = 0; i < authorities.length; i++) granted[i] = new SimpleGrantedAuthority(authorities[i]);
        return web.mutateWith(mockJwt().authorities(granted));
    }

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {
        /** SUPERADMIN reaches the ADMIN-gated seam via the role hierarchy (no explicit
         *  ROLE_ADMIN granted). */
        @Test
        void superadmin_reachesAdminSeam() {
            when(phpbb.stats()).thenReturn(Mono.just(new ForumDto.Stats(1, 2, 3, 0, "live")));
            as("ROLE_USER", "ROLE_SUPERADMIN").get().uri("/bff/forum/admin/stats").exchange()
                    .expectStatus().isOk();
        }
    }

    // ── CROSS-USER (the DENY) ─────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void plainUser_deniedAdminSeam() {
            as("ROLE_USER").get().uri("/bff/forum/admin/stats").exchange()
                    .expectStatus().isForbidden();
        }

        @Test
        void forumUser_deniedAdminSeam() {
            as("ROLE_USER", "ROLE_FORUM").get().uri("/bff/forum/admin/stats").exchange()
                    .expectStatus().isForbidden();
        }
    }
}
