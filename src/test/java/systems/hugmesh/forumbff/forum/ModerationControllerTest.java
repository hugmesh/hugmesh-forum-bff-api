package systems.hugmesh.forumbff.forum;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.forumbff.config.SecurityConfig;
import systems.hugmesh.forumbff.phpbb.PhpbbApiClient;
import systems.hugmesh.forumbff.web.ApiExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The LOAD-BEARING moderation gate: {@code @PreAuthorize("hasRole('ADMIN') or
 * (hasRole('MOD') and hasRole('FORUM'))")} — the AND of MOD+FORUM, NOT
 * {@code hasAnyRole('MOD','ADMIN')}. The critical assertion:
 * <b>ROLE_MOD WITHOUT ROLE_FORUM is FORBIDDEN</b> at moderation (403), while
 * ROLE_MOD + ROLE_FORUM and ROLE_ADMIN are allowed. A plain ROLE_FORUM user (no MOD)
 * is also forbidden from moderation.
 */
@WebFluxTest(controllers = ModerationController.class)
@Import({SecurityConfig.class, ApiExceptionHandler.class})
class ModerationControllerTest {

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

    private WebTestClient with(String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) auths[i] = new SimpleGrantedAuthority(roles[i]);
        return web.mutateWith(mockJwt().authorities(auths));
    }

    @Test
    void moderationQueue_allowedForModWithForum() {
        when(phpbb.stats()).thenReturn(Mono.just(new ForumDto.Stats(0, 0, 0, 4, "live")));
        with("ROLE_USER", "ROLE_MOD", "ROLE_FORUM").get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.queueDepth").isEqualTo(4);
    }

    @Test
    void moderationQueue_allowedForAdmin() {
        when(phpbb.stats()).thenReturn(Mono.just(new ForumDto.Stats(0, 0, 0, 0, "live")));
        with("ROLE_USER", "ROLE_ADMIN").get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isOk();
    }

    /** THE CRITICAL CASE: ROLE_MOD WITHOUT ROLE_FORUM -> 403 (not a moderator). */
    @Test
    void moderationQueue_forbiddenForModWithoutForum() {
        with("ROLE_USER", "ROLE_MOD").get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void moderationQueue_forbiddenForForumUserWithoutMod() {
        with("ROLE_USER", "ROLE_FORUM").get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void moderationQueue_forbiddenForPlainUser() {
        with("ROLE_USER").get().uri("/bff/forum/moderation/queue").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void moderateTopic_allowedForModWithForum() {
        when(phpbb.moderateTopic(anyLong(), any())).thenReturn(Mono.empty());
        with("ROLE_USER", "ROLE_MOD", "ROLE_FORUM").post().uri("/bff/forum/moderation/topics/3")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"action\":\"lock\",\"reason\":\"spam\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.action").isEqualTo("lock");
    }

    @Test
    void moderateTopic_forbiddenForModWithoutForum() {
        with("ROLE_USER", "ROLE_MOD").post().uri("/bff/forum/moderation/topics/3")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"action\":\"lock\"}")
                .exchange().expectStatus().isForbidden();
    }
}
