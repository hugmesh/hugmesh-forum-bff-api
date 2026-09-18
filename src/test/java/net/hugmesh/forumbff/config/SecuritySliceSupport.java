package net.hugmesh.forumbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.forumbff.security.ForumStepUpAccessDeniedHandler;

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
     * The production access-denied renderer the chain beans take as a parameter. Stateless, so
     * one instance serves every slice — and using the REAL one (not a stub) is what makes the
     * step-up signal, and the untouched wire shape of every other 403, observable from a slice.
     */
    static final ForumStepUpAccessDeniedHandler STEP_UP_ACCESS_DENIED =
            new ForumStepUpAccessDeniedHandler();

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
        SecurityWebFilterChain chain = config.devFilterChain(ServerHttpSecurity.http(), STEP_UP_ACCESS_DENIED);
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
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http(), STEP_UP_ACCESS_DENIED);
        return bind(chain, controllers);
    }

    /**
     * Like {@link #sliceClient} but with the D8 MFA flag ON — {@code SecurityConfig} is
     * built with {@code app.mfa.enabled=true} and a 10-minute freshness window, so the
     * privileged-path {@code stepUp} wrappers are LIVE. The dev/test chain is used (the
     * {@code commonRoutes} the step-up wrappers live in is shared by both profiles).
     *
     * <p>The caller must ALSO enable MFA on whatever produces the authorities (the
     * {@code TenancyResourceServerConfig} the multi-issuer slice drives), or no token
     * can ever carry the {@code MFA_SATISFIED} marker the gate demands — the flag is one
     * platform-wide switch and the slice has to mirror that.
     */
    static WebTestClient mfaSliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, true, 600000L);
        SecurityWebFilterChain chain = config.devFilterChain(ServerHttpSecurity.http(), STEP_UP_ACCESS_DENIED);
        return bind(chain, controllers);
    }

    /**
     * Like {@link #mfaSliceClient} but routed through the PROD
     * {@link SecurityConfig#filterChain} — the {@code @Profile("!dev & !test")} chain that
     * every deployment of this service actually runs (compose and the cluster both come up
     * profile-less).
     *
     * <p>It exists because every other slice in this repo builds the DEV chain, so a
     * {@code .exceptionHandling(...)} deleted from the prod chain alone would leave the whole
     * suite green while production lost the step-up signal entirely — the exact mutation a
     * skeptic round caught in hugmesh-mod-bff-api PR #18, on that repo's other chain.
     */
    static WebTestClient mfaProdSliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, true, 600000L);
        SecurityWebFilterChain chain =
                config.filterChain(ServerHttpSecurity.http(), STEP_UP_ACCESS_DENIED);
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
