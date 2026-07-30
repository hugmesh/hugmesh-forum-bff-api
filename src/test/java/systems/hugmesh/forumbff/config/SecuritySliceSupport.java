package systems.hugmesh.forumbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.hugmesh.commons.security.DomainRegistry;

/**
 * Shared scaffolding for the forum-BFF SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig} filter chain (the actual {@code authorizeExchange} path
 * policy + the OAuth2 resource-server wiring), with NO full Spring Boot context.
 *
 * <p>This is the load-bearing half of the copyable multi-issuer pattern (see
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}). COPIED from the hugmesh-gateway
 * reference seam (PR #34, branch {@code test/security-slice-keystone}); adapted to
 * this repo's package, its {@code SecurityConfig} constructor
 * ({@code (DomainRegistry, ObjectProvider<...>)} — same shape as the gateway), and
 * its PROFILE-SPLIT filter-chain beans.
 *
 * <p><b>Profile split.</b> Unlike the gateway's single {@code filterChain(http)},
 * this repo declares two profile-gated chain beans with byte-identical
 * {@code commonRoutes} and only the OpenAPI-spec gating differing:
 * {@code devFilterChain} ({@code @Profile({"dev","test"})}, spec PUBLIC) and
 * {@code filterChain} ({@code @Profile("!dev & !test")}, spec ADMIN/SUPERADMIN).
 * The slice builds them DIRECTLY (no Spring profile activation), so it can exercise
 * either. {@link #sliceClient} uses the dev/test chain (matching the {@code test}
 * profile these slices run under); {@link #prodSliceClient} uses the prod chain so
 * the spec-path ADMIN gate can be asserted too.
 */
abstract class SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real dev/test {@link SecurityConfig#devFilterChain} built from a fresh
     * {@link ServerHttpSecurity}. The chain is installed as a {@link WebFilterChainProxy}
     * web filter so the resource-server authentication + the {@code authorizeExchange}
     * policy run exactly as in production (modulo the spec-path gating, which the dev
     * profile makes public — the prod chain's ADMIN gate is covered by
     * {@link #prodSliceClient}).
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        SecurityWebFilterChain chain = config.devFilterChain(ServerHttpSecurity.http());
        return bind(chain, controllers);
    }

    /**
     * Like {@link #sliceClient} but routed through the PROD {@link SecurityConfig#filterChain}
     * (the {@code @Profile("!dev & !test")} chain whose OpenAPI-spec paths require
     * ADMIN / SUPERADMIN). Use this to assert the prod spec-path gating; every
     * non-spec route is identical to the dev/test chain.
     */
    static WebTestClient prodSliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        return bind(chain, controllers);
    }

    private static WebTestClient bind(SecurityWebFilterChain chain, Object... controllers) {
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);
        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                .build();
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    @SuppressWarnings("unchecked")
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
