package net.hugmesh.forumbff.phpbb;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two wire filters:
 * <ul>
 *   <li>JWT-forwarding — the caller's Casdoor JWT is re-injected as BOTH
 *       {@code Authorization: Bearer <jwt>} AND {@code X-HugMesh-JWT} so the phpBB
 *       extension can validate it against the Casdoor JWKS;</li>
 *   <li>response hygiene — {@code Set-Cookie} is stripped and a {@code text/html}
 *       phpBB-rendered body is dropped (an empty body is returned) so a phpBB login /
 *       ACP / error PAGE can never transit to the client.</li>
 * </ul>
 */
class PhpbbWebClientConfigTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        private final ClientResponse response;
        Recorder(ClientResponse response) { this.response = response; }
        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(response);
        }
    }

    private static Jwt jwt() {
        return Jwt.withTokenValue("the-jwt-value").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("sub-1").build();
    }

    @Test
    void jwtForwardingFilter_injectsBearerAndHugMeshHeader() {
        Recorder rec = new Recorder(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE).body("{}").build());
        WebClient web = WebClient.builder().baseUrl("http://phpbb.test")
                .filter(PhpbbWebClientConfig.jwtForwardingFilter())
                .exchangeFunction(rec).build();

        JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt(), AuthorityUtils.NO_AUTHORITIES);
        Mono<String> call = web.get().uri("/api/v1/hugmesh/categories").retrieve().bodyToMono(String.class)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                        Mono.just(new SecurityContextImpl(auth))));

        StepVerifier.create(call).expectNext("{}").verifyComplete();
        ClientRequest sent = rec.requests.get(0);
        assertThat(sent.headers().getFirst("Authorization")).isEqualTo("Bearer the-jwt-value");
        assertThat(sent.headers().getFirst("X-HugMesh-JWT")).isEqualTo("the-jwt-value");
    }

    @Test
    void jwtForwardingFilter_noJwtInContext_sendsUnauthenticated() {
        Recorder rec = new Recorder(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE).body("{}").build());
        WebClient web = WebClient.builder().baseUrl("http://phpbb.test")
                .filter(PhpbbWebClientConfig.jwtForwardingFilter())
                .exchangeFunction(rec).build();
        // A non-JWT auth must NOT have a broader credential substituted.
        StepVerifier.create(web.get().uri("/x").retrieve().bodyToMono(String.class)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(
                                new SecurityContextImpl(new UsernamePasswordAuthenticationToken("u", "p"))))))
                .expectNext("{}").verifyComplete();
        assertThat(rec.requests.get(0).headers().getFirst("Authorization")).isNull();
    }

    @Test
    void responseHygieneFilter_dropsTextHtmlBody() {
        Recorder rec = new Recorder(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.TEXT_HTML_VALUE)
                .header("Set-Cookie", "phpbb_sid=abc; HttpOnly")
                .body("<html><body>phpBB login</body></html>").build());
        WebClient web = WebClient.builder().baseUrl("http://phpbb.test")
                .filter(PhpbbWebClientConfig.responseHygieneFilter())
                .exchangeFunction(rec).build();
        // The text/html body is dropped to empty so a phpBB page never reaches the client.
        StepVerifier.create(web.get().uri("/").exchangeToMono(r -> r.bodyToMono(String.class).defaultIfEmpty("")))
                .assertNext(body -> assertThat(body).doesNotContain("phpBB login"))
                .verifyComplete();
    }

    @Test
    void responseHygieneFilter_stripsSetCookie() {
        Recorder rec = new Recorder(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .header("Set-Cookie", "phpbb_sid=abc; HttpOnly")
                .body("{}").build());
        WebClient web = WebClient.builder().baseUrl("http://phpbb.test")
                .filter(PhpbbWebClientConfig.responseHygieneFilter())
                .exchangeFunction(rec).build();
        StepVerifier.create(web.get().uri("/x").exchangeToMono(r -> {
                    assertThat(r.headers().header("Set-Cookie")).isEmpty();
                    return r.bodyToMono(String.class).defaultIfEmpty("");
                }))
                .assertNext(body -> assertThat(body).isEqualTo("{}"))
                .verifyComplete();
    }
}
