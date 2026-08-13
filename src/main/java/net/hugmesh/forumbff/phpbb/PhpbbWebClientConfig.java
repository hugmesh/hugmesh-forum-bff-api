package net.hugmesh.forumbff.phpbb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

/**
 * Wires the reactive {@link WebClient} the {@link PhpbbApiClient} +
 * {@link net.hugmesh.forumbff.external.PhpbbAdminClient} use to call the phpBB
 * {@code hugmesh/forum-api} extension (the in-cluster phpBB upstream). Mirrors the
 * user-bff / mod-bff {@code FederationWebClientConfig} + {@code FederationHttpClientSsl}.
 *
 * <p><b>JWT-forwarding filter</b> ({@link #jwtForwardingFilter}): reads the CURRENT
 * request's Casdoor JWT out of the reactive security context and re-injects its raw
 * token value BOTH as {@code Authorization: Bearer <jwt>} AND as the
 * {@code X-HugMesh-JWT} header. The extension validates the token against the
 * Casdoor JWKS on EVERY request and re-derives group membership / ROLE_ADMIN from the
 * verified token — it NEVER trusts caller-supplied group data. Forwarding the caller's
 * identity is what makes "acts-as-user" (author/timestamp recorded under that phpBB
 * user, keyed by Casdoor {@code sub}) possible with no shared service principal.
 *
 * <p><b>Response-hygiene filter</b> ({@link #responseHygieneFilter}): a phpBB install
 * can render an HTML login / ACP / error page; that must NEVER transit to the client.
 * This filter strips {@code Set-Cookie} (the extension runs stateless — no phpBB
 * session cookie should ever leave this BFF) and rejects any non-JSON
 * ({@code text/html}) phpBB body so a phpBB-rendered page cannot leak through.
 *
 * <p>When {@code hugmesh.mtls.client.enabled=true} (default OFF) the WebClient is
 * given a reactor-netty connector that presents this BFF's PKI client identity and
 * trusts the cluster CA (see {@link PhpbbHttpClientSsl}). Base URL defaults to the
 * in-cluster phpbb Service DNS in the dedicated {@code hugmesh-forum} namespace
 * (env-overridable via {@code PHPBB_API_BASE_URL}).
 */
@Configuration
@EnableConfigurationProperties(PhpbbHttpClientSsl.class)
public class PhpbbWebClientConfig {

    private static final Logger log = LoggerFactory.getLogger(PhpbbWebClientConfig.class);

    /** The header the phpBB extension reads in addition to standard Authorization. */
    static final String HUGMESH_JWT_HEADER = "X-HugMesh-JWT";

    /**
     * The reactive WebClient to the phpBB extension. Carries the JWT-forwarding filter
     * (Bearer + X-HugMesh-JWT) and the response-hygiene filter (strip Set-Cookie,
     * drop text/html). mTLS client-cert presentation is applied when enabled.
     */
    @Bean
    WebClient phpbbWebClient(
            PhpbbHttpClientSsl mtls,
            @Value("${phpbb.api.base-url:http://phpbb.hugmesh-forum.svc.cluster.local:80}") String baseUrl) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(jwtForwardingFilter())
                .filter(responseHygieneFilter())
                .build();
    }

    /**
     * The headless read/write client to the extension {@code /api/v1/hugmesh/**}.
     * GATED stub-seam: {@code phpbb.enabled} (default false) — never hard-fail; the
     * single external-call seam lives in {@link PhpbbApiClient}.
     */
    @Bean
    PhpbbApiClient phpbbApiClient(
            WebClient phpbbWebClient,
            @Value("${phpbb.enabled:false}") boolean enabled) {
        if (!enabled) {
            log.info("[phpbb] PhpbbApiClient is STUB-SEAMED (phpbb.enabled=false) — "
                    + "extension calls return typed degraded/empty; flip phpbb.enabled=true once the "
                    + "hugmesh/forum-api extension shape is pinned on-cluster");
        }
        return new PhpbbApiClient(phpbbWebClient, enabled);
    }

    /**
     * Re-injects the caller's Casdoor JWT (from the reactive security context) as the
     * outbound {@code Authorization} header AND the {@code X-HugMesh-JWT} header. If
     * there is no JWT in context (e.g. a non-request-scoped call) the request goes out
     * unauthenticated and the extension rejects it — by design, the BFF never
     * substitutes a broader-scoped credential.
     */
    static ExchangeFilterFunction jwtForwardingFilter() {
        // Delegate to a named helper so the outer lambda stays within the body-length limit.
        return (request, next) -> forwardJwt(request, next);
    }

    /**
     * Reads the caller's Casdoor JWT from the reactive security context and rebuilds the
     * outbound request with {@code Authorization: Bearer} and {@code X-HugMesh-JWT} set.
     * If no JWT is present the request passes through unauthenticated — the extension will
     * reject it, which is the correct fail-closed behaviour.
     */
    private static Mono<ClientResponse> forwardJwt(
            ClientRequest request,
            ExchangeFunction next) {
        // Lift the current JWT from the reactive security context.
        return ReactiveSecurityContextHolder.getContext()
                // Extract the Authentication from the security context.
                .map(SecurityContext::getAuthentication)
                // Only proceed when the principal is a JWT-backed token.
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                // Unwrap the Jwt object from the authentication token.
                .map(auth -> ((JwtAuthenticationToken) auth).getToken())
                // Pull the raw token string from the Jwt object.
                .map(Jwt::getTokenValue)
                // Rebuild the outbound request with both JWT headers injected.
                .map(token -> ClientRequest.from(request)
                        .headers(h -> {
                            h.setBearerAuth(token);
                            h.set(HUGMESH_JWT_HEADER, token);
                        })
                        .build())
                // Fall back to the original request when no JWT is in context.
                .defaultIfEmpty(request)
                // Hand the (possibly enriched) request to the next filter in the chain.
                .flatMap(next::exchange);
    }

    /**
     * Drops any phpBB-rendered HTML body and strips {@code Set-Cookie} so a phpBB
     * login / ACP / error page can never transit to the client, and the extension's
     * stateless (no phpBB session) contract is enforced at the wire. A {@code text/html}
     * response is replaced with an empty body carrying the upstream status so the
     * client only ever sees JSON or a clean status — never a phpBB page.
     */
    static ExchangeFilterFunction responseHygieneFilter() {
        // Thin lambda: pick the html-vs-json branch; each branch is a NAMED helper below.
        return ExchangeFilterFunction.ofResponseProcessor(response ->
                isHtml(response) ? dropHtmlPage(response) : stripCookiesPreserveBody(response));
    }

    /** True iff the upstream phpBB response carries a {@code text/html} content type. */
    private static boolean isHtml(ClientResponse response) {
        MediaType contentType = response.headers().contentType().orElse(null);
        return contentType != null && contentType.includes(MediaType.TEXT_HTML);
    }

    /**
     * HTML branch — a phpBB-rendered login / ACP / error page must NEVER transit to the
     * client: release the upstream body and replace it with an empty body that keeps the
     * upstream status, stripping {@code Set-Cookie} on the way out.
     */
    private static Mono<ClientResponse> dropHtmlPage(ClientResponse response) {
        log.warn("[phpbb] dropped a text/html phpBB response (status={}) — a phpBB-rendered "
                + "page must never transit to the client", response.statusCode());
        return response.releaseBody()
                .thenReturn(response.mutate()
                        .headers(h -> h.remove("Set-Cookie"))
                        .body("")
                        .build());
    }

    /**
     * Non-HTML (JSON) branch — strip {@code Set-Cookie} but PRESERVE the body stream.
     * {@code ClientResponse.mutate()} (Spring 7; replaces the removed static {@code .from()})
     * copies status/headers/strategies but NOT the body, so the original body data buffers
     * are re-attached explicitly (otherwise the JSON would be dropped too).
     */
    private static Mono<ClientResponse> stripCookiesPreserveBody(ClientResponse response) {
        // mutate() PRESERVES the original body by itself — do NOT re-set it via
        // response.bodyToFlux(...). Doing so wires the mutated response's body to a
        // SECOND subscription of the same Reactor Netty inbound, and the first real
        // JSON 200 through this filter dies with
        //   IllegalStateException: Rejecting additional inbound receiver
        // AFTER the extension already answered 200 — reading as an upstream fault.
        // The bug was invisible for the filter's whole life: with the phpbb seam
        // dark no call happened at all, and against a board without the extension
        // every response took the isHtml/error branch, so no JSON body ever
        // transited here until the real extension came up.
        return Mono.just(response.mutate()
                .headers(h -> h.remove("Set-Cookie"))
                .build());
    }
}
