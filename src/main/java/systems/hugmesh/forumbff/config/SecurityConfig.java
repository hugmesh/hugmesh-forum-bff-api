package systems.hugmesh.forumbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.security.CasdoorAuthorities;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.forumbff.security.PrincipalDomain;

/**
 * Casdoor-aware OAuth2 resource-server security for the forum BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates any
 * {@code @PreAuthorize} gates on the controllers. The JWT→authority mapping is
 * delegated to the shared {@link CasdoorAuthorities} converter — COPIED (logic) from
 * the adversarially-verified-safe hugmesh-gateway so the BFF and the gateway emit
 * BYTE-IDENTICAL authorities, including the reserved-prefix injection guard on
 * {@code permissions} and exactly one issuer-derived {@code DOMAIN_<x>} tenant
 * authority.
 *
 * <p><b>Wrap-per-role-and-action.</b> The forum surface is gated by ROLE_FORUM at the
 * fe-gateway (route-access). This filter chain is DEFENCE IN DEPTH on top of that:
 * <ul>
 *   <li>{@code /bff/forum/admin/**} -> {@code hasRole('ADMIN')} — the admin-console seam
 *       admin-bff calls (ban/unban/group-assign/category CRUD/styles/extensions/stats).
 *       Kept on a path gated ADMIN end-to-end so an admin WITHOUT ROLE_FORUM is not
 *       blocked by the user floor (the converter gives admins neither ROLE_FORUM nor a
 *       superset). Declared FIRST so the more specific path wins over the floor below.</li>
 *   <li>{@code /bff/forum/**} -> {@code .authenticated()} — the ROLE_FORUM floor is
 *       enforced at the gateway; the converter adds ROLE_USER to every principal so
 *       {@code .authenticated()} proves authentication. Ownership/role re-checks (and the
 *       {@code /bff/forum/moderation/**} AND-of-MOD+FORUM gate) live at the METHOD level
 *       via {@code @PreAuthorize} (NOT here as {@code hasAnyRole}, which cannot express the
 *       AND).</li>
 * </ul>
 *
 * <p><b>Domain-scope (multi-brand).</b> The forum admin/mod surfaces operate on
 * per-domain request-scoped data — the {@code forum_action} audit trail and the
 * {@code forum_user_role} binding cache. An admin/mod of brand X must see only brand
 * X's rows; the service/repo layers add a {@code domain = :domain} predicate derived
 * SERVER-SIDE from the validated issuer ({@link PrincipalDomain}), with SUPERADMIN
 * unscoped. The ROLE_FORUM / ROLE_FORUM_MOD seams are untouched; owner==JWT-subject
 * ({@code ForumService.isOwnerOrAdmin}) is UNWEAKENED.
 *
 * <p><b>Multi-issuer is OPT-IN + backward-compatible.</b> When
 * {@code app.tenancy.issuers} carries per-brand issuer=domain pairs
 * ({@link TenancyResourceServerConfig} contributes a resolver AND the registry is
 * {@link DomainRegistry#isMultiIssuer()}), each trusted per-brand Casdoor validates
 * its own tokens (unknown {@code iss} → 401). Otherwise the resource server stays on
 * the existing single {@code o.jwt(...)} issuer-uri path — byte-for-byte unchanged.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
// SecurityConfig depends on DomainRegistry (the converter stamps the issuer-derived
// DOMAIN_<x>); PrincipalDomain is the controllers'/service's single domain-resolution
// bean. Importing both here means every @WebFluxTest slice that imports SecurityConfig
// gets them too — the slice context loads without each test re-declaring them.
@Import({DomainRegistry.class, PrincipalDomain.class})
public class SecurityConfig {

    /** Issuer→domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no issuer
     *  at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider value)
     *  ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays on
     *  the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the current
     *  single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** D8 MFA derivation config (ships dark). {@code app.mfa.enabled} default false:
     *  when off the converter emits the byte-identical legacy authority set and the
     *  {@code MFA_SATISFIED} marker is NEVER produced. {@code app.mfa.freshness-window}
     *  default 10m (600000ms). Threaded into {@link CasdoorAuthorities.MfaConfig} so the
     *  single-issuer + multi-issuer paths derive the marker identically. */
    private final boolean mfaEnabled;
    private final long mfaFreshnessWindowMillis;

    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
    }

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface. {@code /v3/api-docs} is the raw
     * OpenAPI JSON the platform ng-openapi-gen typed clients (the paired
     * hugmesh-forum-ui) + the docs pipeline fetch. Gated per profile (see the two
     * filter-chain beans): public under dev/test so {@code gen:fetch} can curl the
     * spec without a token, ROLE_ADMIN / SUPERADMIN everywhere else (prod) so the API
     * contract is never publicly reachable — matching the user-bff / admin-bff template.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The
     * ONLY difference between the two profiles is how {@link #SPEC_PATHS} is gated,
     * so every other route lives here to keep the two chains in lockstep and make
     * it impossible to loosen a non-spec route by editing only one chain.
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // The admin-console seam — ADMIN (or the cross-domain SUPERADMIN super-role)
        // end-to-end (declared BEFORE the floor so the more-specific prefix matches
        // first). Admins reach it via the converter's ROLE_ADMIN with no ROLE_FORUM
        // needed; SUPERADMIN reaches it via the role hierarchy edge.
        ex.pathMatchers("/bff/forum/admin/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // The whole forum surface — the ROLE_FORUM floor is enforced at the gateway, so
        // .authenticated() proves authentication here. The moderation AND-of-MOD+FORUM
        // gate + ownership are re-checked at the method level (@PreAuthorize) in the
        // controllers/service — NOT here, because hasAnyRole cannot express the AND.
        ex.pathMatchers("/bff/forum/**").authenticated();
    }

    /**
     * Hardened reactive HTTP-security headers — the API-defensive MINIMUM for a
     * pure-JSON resource server that always sits BEHIND the hugmesh-gateway
     * (the single TLS-terminating PEP, NIST 800-228 sec 3-4). The full
     * browser-policy set (HSTS, Permissions-Policy, COOP/CORP, UI-shell CSP) is
     * emitted ONCE at the gateway front door so all brands/BFFs inherit it and the
     * per-BFF configs can't drift; this BFF re-asserts only the defense-in-depth
     * minimum.
     *
     * <p>Applied identically to BOTH the dev/test and prod chains via a shared
     * helper so the two profiles can never drift on header policy.
     *
     * <ul>
     *   <li><b>Content-Security-Policy: {@code default-src 'none'; frame-ancestors
     *       'none'}</b> — this BFF never serves HTML/documents, so the safest CSP is
     *       the deny-everything one (defense in depth, not a document policy). NOT the
     *       UI-shell value — that belongs only at the gateway/UI host.</li>
     *   <li><b>Referrer-Policy: {@code no-referrer}</b> — kept EXPLICIT (also Spring's
     *       default) so it survives a future default change.</li>
     *   <li><b>X-Content-Type-Options: {@code nosniff}</b>, <b>X-Frame-Options:
     *       {@code DENY}</b> and <b>Cache-Control</b> are Spring Security reactive
     *       SECURE DEFAULTS — left implicit and NOT disabled.</li>
     * </ul>
     *
     * <p><b>Deliberately omitted on a JSON BFF:</b> HSTS (meaningless over the
     * plaintext intra-mesh hop — it lives only at the TLS front door) and
     * Permissions-Policy / COOP / CORP (no-document API has no browsing context to
     * police). These are NOT gaps here — see the header policy in the audit plan.
     */
    private static void hardenedHeaders(ServerHttpSecurity.HeaderSpec headers) {
        headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'none'; frame-ancestors 'none'"))
                .referrerPolicy(rp -> rp.policy(
                        ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER));
        // X-Frame-Options DENY + X-Content-Type-Options nosniff + Cache-Control are
        // Spring reactive defaults — left implicit (must NOT be disabled).
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC so
     * {@code gen:fetch} (ng-openapi-gen) and the docs pipeline can curl
     * {@code /v3/api-docs} locally without a Casdoor token. Activate with
     * {@code SPRING_PROFILES_ACTIVE=dev} (or the {@code test} profile the slice
     * tests use). Every non-spec route is identical to prod.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::hardenedHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN (or the
     * cross-domain SUPERADMIN super-role) so the API contract is never publicly
     * reachable. Mirrors the user-bff / admin-bff profile split. Every non-spec route
     * is identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::hardenedHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Wire the OAuth2 resource server. Multi-issuer is OPT-IN: swap to the per-issuer
     * authentication-manager resolver ONLY when BOTH a resolver was contributed by
     * {@link TenancyResourceServerConfig} AND the registry is genuinely multi-issuer
     * (more than the single back-compat entry). Gating on {@code isMultiIssuer()} —
     * not merely {@code resolver != null} — keeps a single-issuer cluster on the
     * EXISTING issuer-uri {@code o.jwt(...)} decoder path even if the tenancy
     * conditional ever activates with just the lone back-compat issuer. In true
     * multi-brand mode each trusted per-brand Casdoor validates its own tokens
     * (unknown iss -> 401, fail-closed).
     */
    private void resourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges. Deliberately MINIMAL:
     * SUPERADMIN is a strict superset of admin/mod/user, but {@code ROLE_ADMIN} and
     * {@code ROLE_MOD} are documented SIBLINGS (no {@code ADMIN > MOD} edge) and the
     * AND-intersection composites ({@code ROLE_FORUM_MOD = ROLE_MOD ∩ ROLE_FORUM},
     * {@code ROLE_*_EXTERNAL_CLIENT}) are intentionally ABSENT — so a hierarchy can
     * NEVER let a plain ADMIN satisfy the MOD-AND-FORUM moderation gate. This bean
     * only smooths {@code @PreAuthorize} ergonomics + lets SUPERADMIN reach the
     * admin-gated forum-admin + spec surfaces; the actual cross-surface authorization
     * (and the domain-scope) is enforced by the service layer.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    /**
     * Wire the {@link #roleHierarchy()} into REACTIVE method security so the
     * {@code @PreAuthorize("hasRole('ADMIN')")} gates honour {@code ROLE_SUPERADMIN >
     * ROLE_ADMIN} — i.e. the cross-domain SUPERADMIN reaches the ADMIN-only
     * forum-admin methods without an explicit {@code ROLE_ADMIN}. (A bare
     * {@code RoleHierarchy} bean is NOT auto-applied to {@code @PreAuthorize} in the
     * reactive method-security path, so the expression handler is set explicitly.)
     * The hierarchy is still deliberately MINIMAL — it never crosses the MOD-AND-FORUM
     * AND-composite (that gate stays an explicit AND in {@link ModerationController}).
     */
    // setRoleHierarchy/setDefaultRolePrefix are deprecated (since Spring Security 7.0,
    // not yet forRemoval) in favour of wiring an AuthorizationManagerFactory. That
    // factory-based path changes how @PreAuthorize SpEL expressions resolve
    // hasRole()/role-hierarchy at runtime, so swapping it in here — on the
    // security-critical SUPERADMIN role-hierarchy gate — without a dedicated,
    // adversarially-verified behavioural check would risk a silent authorization
    // regression. Suppressing rather than migrating blind; revisit alongside a
    // focused security-behavior verification pass.
    @SuppressWarnings("deprecation")
    @Bean
    MethodSecurityExpressionHandler forumMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        // Keep the default ROLE_ prefix explicit so hasRole('ADMIN') maps to ROLE_ADMIN.
        handler.setDefaultRolePrefix(new GrantedAuthorityDefaults("ROLE_").getRolePrefix());
        return handler;
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT → authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical —
     * three claim sources ({@code roles} → {@code ROLE_<UPPER>}, {@code permissions}
     * verbatim MINUS reserved-prefix injection, legacy {@code isAdmin} →
     * {@code ROLE_ADMIN}), a {@code ROLE_USER} floor, plus exactly one issuer-derived
     * {@code DOMAIN_<x>} authority (NON-role; {@code DOMAIN_default} for the
     * single-issuer fallback so this cluster is unchanged).
     */
    Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis));
    }
}
