# Multi-issuer security-slice tests

This repo follows the **multi-issuer security-slice pattern** used across the HugMesh
BFF family. The pattern started in
[`hugmesh-gateway`](https://github.com/hugmesh/hugmesh-gateway)'s own
`docs/testing/MULTI-ISSUER-SLICE.md`. The slice proves that this WebFlux OAuth2
resource server handles **per-brand (multi-issuer) Casdoor tokens** correctly. It
guards the property that matters most: an **unknown issuer fails closed (401)**, and a
token from one brand can **never** authenticate as another.

The tests are deterministic. They need **no network access and no live Casdoor**. A
tiny in-process JDK `HttpServer` bound to `127.0.0.1` serves each brand's JWKS and
OIDC discovery document, so `ReactiveJwtDecoders.fromIssuerLocation(...)` validates
real RSA-signed tokens entirely offline. The slice tests need no Docker. The
full-context test (`MultiIssuer401FailClosedSpringBootTest`) extends the commons
`PostgresTestSupport`, so it starts a Testcontainers Postgres and needs Docker.

## Shared test infrastructure

- `src/test/java/net/hugmesh/forumbff/testsupport/TestIssuer.java` mints
  issuer-specific RS256 JWTs against an in-process JWKS. It was copied from the
  gateway reference seam. Only the package declaration changed, plus one forum-bff
  addition: `jwkSetUri()` and `registerAsBackCompatIssuer(...)` (see the full-context
  test below). It serves the discovery document at `/.well-known/openid-configuration`
  and the JWK set at `/.well-known/jwks.json`. Its only dependency is
  `nimbus-jose-jwt`, which comes in through `spring-boot-starter-oauth2-resource-server`.
- `src/test/java/net/hugmesh/forumbff/config/SecuritySliceSupport.java` builds this
  repo's real `SecurityConfig` filter chain into a `WebTestClient`, without booting a
  full Spring Boot context. It is adapted to this repo's
  `SecurityConfig(DomainRegistry, ObjectProvider<...>, boolean mfaEnabled, long
  mfaFreshnessWindowMillis)` constructor and its profile-split filter chain beans:
  `devFilterChain` (`@Profile({"dev","test"})`, spec public), reached via
  `sliceClient(...)`, and `filterChain` (`@Profile("!dev & !test")`, spec
  ADMIN-gated), reached via `prodSliceClient(...)`. `mfaSliceClient(...)` and
  `mfaProdSliceClient(...)` build the same two chains with `app.mfa.enabled=true`.

## The tests

### `MultiIssuerSecuritySliceTest` — the core scenarios and their fail-closed neighbours

| # | Scenario | Expectation |
|---|----------|-------------|
| (a) | trusted brand-X JWT | authenticated; `DOMAIN_brandx` emitted, never `DOMAIN_brandy`/`DOMAIN_default` |
| (b) | well-formed, correctly-signed JWT from an **unlisted** issuer | **401 fail-closed** — the resolver returns `Mono.empty()`, with no default-accept fallback |
| (c) | trusted brand-Y JWT | scoped to `DOMAIN_brandy`; never `DOMAIN_brandx` |
| + | tampered signature / wrong `kid` / garbage bearer token | 401 |

### `MultiIssuer401FailClosedSpringBootTest` — full-context fail-closed coverage

A `@SpringBootTest(webEnvironment = RANDOM_PORT)` test boots the whole application
(`test` profile, real auto-configuration) with `app.tenancy.issuers` wired from two
in-process `TestIssuer`s through `@DynamicPropertySource`. A third, unlisted
`TestIssuer` plays the foreign issuer. The slice tests above build
`SecurityConfig`/`TenancyResourceServerConfig` by hand. This test exercises the
production wiring end to end:

- the `@ConditionalOnExpression` activation of the tenancy resolver bean;
- the `DomainRegistry` built from the real property;
- `SecurityConfig.resourceServer` choosing the multi-issuer resolver path only when
  `resolver != null && domainRegistry.isMultiIssuer()`.

An assertion pins that the booted context took the multi-issuer path, so the
fail-closed behaviour below is the resolver's own.

The backward-compatible single-issuer `issuer-uri` and `jwk-set-uri` properties both
point at brand X (`TestIssuer.registerAsBackCompatIssuer`).
`TenancyResourceServerConfig` validates the issuer equal to `issuer-uri` through
`jwk-set-uri`, and every other listed brand through OIDC discovery. With only
`issuer-uri` overridden, `jwk-set-uri` stays at `application.yml`'s
`https://id.hugmesh.net/.well-known/jwks` default, and brand-X tokens fail with a 500
off-host (issue #19).

| # | Scenario | Expectation |
|---|----------|-------------|
| (a) | token from a valid configured issuer (brand X or brand Y) | **200**; stamped with its own `DOMAIN_<brand>` only, never another brand's |
| (b) | token from a foreign/unconfigured issuer (well-formed, correctly signed) | **401 fail-closed** — never silently accepted, never treated as anonymous |
| (c) | tampered-signature or wrong-`kid` token | **401** — the platform refuses any token it cannot cryptographically verify |
| + | garbage bearer / missing bearer | 401 |

`TestIssuer.mintWithWrongKid(...)` mints a token signed by the issuer's real private
key and stamped with its real `iss`, but under a JWS-header `kid` that is absent from
the published JWK set. The decoder cannot find a verification key and rejects it. This
differs from a tampered payload (which fails the signature check) and from a foreign
issuer (which the allowlist rejects before any key lookup).

### `SecurityConfigPathGateSliceTest` — coarse `authorizeExchange` behaviour, real tokens

- `/actuator/health` is public (no token required).
- `/bff/forum/**` floors at `.authenticated()` (401 unauthenticated, allowed once
  authenticated).
- An unknown-issuer token gets a **401 end to end**.
- `/bff/forum/admin/**` requires ADMIN/SUPERADMIN. A plain user gets **403**, and so
  does a bare MOD (there is no `ADMIN > MOD` edge). ADMIN and SUPERADMIN are allowed.
  An unauthenticated request gets 401.
- On the production chain, `/v3/api-docs` requires ADMIN (plain user 403,
  unauthenticated 401).

`MfaStepUpPathGateSliceTest` covers the same gates with `app.mfa.enabled` on and off.
With the flag off, an admin with no stamp is still allowed. With it on, the admin and
moderation paths answer 403 without a fresh `MFA_SATISFIED` marker. The refusal
carries the `X-Step-Up-Required` header only when the marker leg denied. The ordinary
`/bff/forum/**` floor is not step-up gated.

## The missing ADMIN>MOD edge is enforced at the method level, not the path level

The load-bearing "MOD AND FORUM" moderation rule is enforced at the **method** level
(`@PreAuthorize("hasRole('ADMIN') or (hasRole('MOD') and hasRole('FORUM'))")` in
`ModerationController`), not in `authorizeExchange`. The coarse path policy only
floors `/bff/forum/moderation/**` to `.authenticated()` (plus the `MFA_SATISFIED`
marker when `app.mfa.enabled` is on). So at the filter-chain layer, a bare
authenticated token passes the moderation **path**. The 403 for a MOD-without-FORUM
caller comes later, at the method gate (covered by `ModerationControllerTest`).

The path-gate slice test asserts the coarse layer's actual decision *and* documents
this boundary. Suppose a refactor moved moderation gating into `authorizeExchange`.
There `hasAnyRole` cannot express an AND, and a bare ADMIN would wrongly pass. The
test would catch it at once.

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set yields **no** authentication manager at all. So
`JwtIssuerReactiveAuthenticationManagerResolver` returns a 401 **before any authority
is emitted**. No fallback "default" manager exists that could accept an unlisted
brand. Scenario (b) in both test classes above is the regression guard that keeps it
that way.
