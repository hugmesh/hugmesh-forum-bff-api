package net.hugmesh.forumbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import net.hugmesh.commons.security.CasdoorAuthorities;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * USER-SITUATIONAL unit test for the Casdoor JWT -> authority converter (the canonical
 * {@link CasdoorAuthorities}, COPIED from the adversarially-verified-safe
 * hugmesh-gateway): ROLE_USER floor; roles (string or {name}) -> ROLE_<UPPER>;
 * permissions verbatim MINUS the reserved-prefix injection guard; isAdmin ->
 * ROLE_ADMIN; plus exactly one issuer-derived DOMAIN_<x>. The {@code forum}/{@code mod}
 * role mappings the forum-BFF gating depends on are asserted explicitly.
 *
 * <p>The CROSS-USER authority-injection regressions (forged
 * {@code permissions:["DOMAIN_other"]} / {@code ["ROLE_SUPERADMIN"]}) live in
 * {@code CasdoorAuthoritiesInjectionTest}.
 */
class SecurityConfigConverterTest {

    /** Single-issuer registry (no config): every token -> DOMAIN_default. */
    private static final DomainRegistry SINGLE = new DomainRegistry("", "");

    private List<String> authorities(Jwt jwt) {
        return CasdoorAuthorities.converter(SINGLE)
                .convert(jwt)
                .map(GrantedAuthority::getAuthority)
                .collectList()
                .block();
    }

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
    }

    @Test
    void floorIsRoleUserPlusDomain() {
        assertThat(authorities(base().build()))
                .containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_default");
    }

    @Test
    void stringRolesBecomeRolePrefixedUppercase_includingForumAndMod() {
        Jwt jwt = base().claim("roles", List.of("forum", "mod", "admin")).build();
        assertThat(authorities(jwt)).contains("ROLE_USER", "ROLE_FORUM", "ROLE_MOD", "ROLE_ADMIN", "DOMAIN_default");
    }

    @Test
    void objectRolesWithNameAreMapped() {
        Jwt jwt = base().claim("roles", List.of(Map.of("name", "forum"))).build();
        assertThat(authorities(jwt)).contains("ROLE_FORUM");
    }

    @Test
    void permissionsArePassedThroughVerbatim() {
        Jwt jwt = base().claim("permissions", List.of("urn:forum:post")).build();
        assertThat(authorities(jwt)).contains("urn:forum:post");
    }

    @Test
    void isAdminTrueAddsRoleAdmin() {
        Jwt jwt = base().claim("isAdmin", true).build();
        assertThat(authorities(jwt)).contains("ROLE_ADMIN");
    }

    @Test
    void converterReturnsFlux() {
        Flux<GrantedAuthority> flux = CasdoorAuthorities.converter(SINGLE).convert(base().build());
        assertThat(flux.collectList().block()).isNotEmpty();
    }
}
