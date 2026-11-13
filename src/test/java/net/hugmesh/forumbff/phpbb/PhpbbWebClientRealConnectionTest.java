package net.hugmesh.forumbff.phpbb;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.hugmesh.forumbff.external.PhpbbAdminClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.UnsupportedMediaTypeException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The phpBB WebClient filters on a REAL Reactor Netty connection to a local HTTP server.
 *
 * <p>{@link PhpbbWebClientConfigTest} feeds the filters in-memory {@code ClientResponse}s,
 * whose bodies can be subscribed any number of times. A Reactor Netty inbound accepts ONE
 * subscriber; a second one while the body is still arriving gets
 * {@code IllegalStateException: Rejecting additional inbound receiver}. The live phpBB smoke
 * test (run 42772063995) hit exactly that: phpBB answered the ban with a 503 text/html error
 * page, the HTML branch of the hygiene filter subscribed that page's body twice, and the ban
 * was audited as {@code degraded:IllegalStateException} instead of {@code degraded:http-503}.
 *
 * <p>Against the old filter the error-page cases failed on every local run, whether the
 * page came with the headers or after them. One earlier live run recorded the same refusal
 * as a plain 503, so the outcome can depend on timing; the server here can hold the body
 * back after the headers to cover the slow case as well.
 */
class PhpbbWebClientRealConnectionTest {

    private static final Duration WAIT = Duration.ofSeconds(10);
    private static final String JSON = "application/json";
    private static final String HTML = "text/html; charset=UTF-8";
    private static final String PAGE = "<html><body>General Error: SQL ERROR [ postgres ]</body></html>";
    private static final String COOKIE = "phpbb3_sid=abc123; path=/; HttpOnly";

    /** What the fake phpBB answers. {@code holdBodyMillis > 0} sends the headers first, then waits. */
    private record Reply(int status, String contentType, String setCookie, String body, long holdBodyMillis) {
    }

    private HttpServer phpbb;
    private String baseUrl;
    private volatile Reply reply;

    @BeforeEach
    void startPhpbb() throws IOException {
        phpbb = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        phpbb.createContext("/", this::answer);
        phpbb.start();
        baseUrl = "http://127.0.0.1:" + phpbb.getAddress().getPort();
    }

    @AfterEach
    void stopPhpbb() {
        phpbb.stop(0);
    }

    private void answer(HttpExchange ex) throws IOException {
        ex.getRequestBody().readAllBytes();
        Reply r = reply;
        byte[] body = r.body().getBytes(StandardCharsets.UTF_8);
        if (r.contentType() != null) {
            ex.getResponseHeaders().add("Content-Type", r.contentType());
        }
        if (r.setCookie() != null) {
            ex.getResponseHeaders().add("Set-Cookie", r.setCookie());
        }
        ex.sendResponseHeaders(r.status(), body.length == 0 ? -1 : body.length);
        if (body.length > 0) {
            OutputStream out = ex.getResponseBody();
            if (r.holdBodyMillis() > 0) {
                out.flush();
                try {
                    Thread.sleep(r.holdBodyMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            out.write(body);
        }
        ex.close();
    }

    /** The production bean: default connector, jwtForwardingFilter then responseHygieneFilter. */
    private WebClient productionClient() {
        return new PhpbbWebClientConfig().phpbbWebClient(new PhpbbHttpClientSsl(), baseUrl);
    }

    /**
     * The production filters in production order on a ONE-connection pool, so a response
     * whose connection is never released makes the next call wait for the pool and time out.
     */
    private WebClient oneConnectionClient(ConnectionProvider pool) {
        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(HttpClient.create(pool)))
                .filter(PhpbbWebClientConfig.jwtForwardingFilter())
                .filter(PhpbbWebClientConfig.responseHygieneFilter())
                .build();
    }

    private static Mono<ResponseEntity<Void>> post(WebClient web) {
        return web.post().uri("/api/v1/hugmesh/admin/users/{sub}/ban", "sub-1")
                .bodyValue("{\"reason\":\"spam\"}")
                .retrieve()
                .toBodilessEntity();
    }

    // -------------------------------------------------------------------------
    // JSON answers (the extension's own): untouched apart from Set-Cookie
    // -------------------------------------------------------------------------

    @Test
    void json200_withoutSetCookie_bodilessEntityIs200() {
        reply = new Reply(200, JSON, null, "{\"ok\":true}", 50);
        StepVerifier.create(post(productionClient()))
                .assertNext(e -> assertThat(e.getStatusCode().value()).isEqualTo(200))
                .expectComplete()
                .verify(WAIT);
    }

    @Test
    void json200_withSetCookie_bodilessEntityIs200_andTheCookieIsStripped() {
        reply = new Reply(200, JSON, COOKIE, "{\"ok\":true}", 50);
        StepVerifier.create(post(productionClient()))
                .assertNext(e -> {
                    assertThat(e.getStatusCode().value()).isEqualTo(200);
                    assertThat(e.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
                })
                .expectComplete()
                .verify(WAIT);
    }

    @Test
    void json200_withSetCookie_bodyStillArrives() {
        reply = new Reply(200, JSON, COOKIE, "{\"ok\":true}", 50);
        StepVerifier.create(productionClient().get().uri("/api/v1/hugmesh/categories")
                        .retrieve().bodyToMono(String.class))
                .expectNext("{\"ok\":true}")
                .expectComplete()
                .verify(WAIT);
    }

    // -------------------------------------------------------------------------
    // text/html answers (a phpBB-rendered page): body dropped, status kept
    // -------------------------------------------------------------------------

    @Test
    void htmlErrorPage_bodyAfterHeaders_surfacesAsItsHttpStatus() {
        reply = new Reply(503, HTML, COOKIE, PAGE, 200);
        StepVerifier.create(post(productionClient()))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(WebClientResponseException.class)
                        .satisfies(w -> assertThat(((WebClientResponseException) w).getStatusCode().value())
                                .isEqualTo(503)))
                .verify(WAIT);
    }

    @Test
    void htmlErrorPage_bodyWithHeaders_surfacesAsItsHttpStatus() {
        reply = new Reply(503, HTML, null, PAGE, 0);
        StepVerifier.create(post(productionClient()))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(WebClientResponseException.class)
                        .satisfies(w -> assertThat(((WebClientResponseException) w).getStatusCode().value())
                                .isEqualTo(503)))
                .verify(WAIT);
    }

    @Test
    void htmlPage200_neverReachesTheCaller() {
        reply = new Reply(200, HTML, COOKIE, PAGE, 200);
        StepVerifier.create(productionClient().get().uri("/").exchangeToMono(r -> {
                    assertThat(r.headers().header(HttpHeaders.SET_COOKIE)).isEmpty();
                    return r.bodyToMono(String.class).defaultIfEmpty("");
                }))
                .assertNext(body -> assertThat(body).isEmpty())
                .expectComplete()
                .verify(WAIT);
    }

    /**
     * A typed read of a 200 HTML page still fails: the dropped page keeps its text/html
     * type, which no JSON decoder reads, so phpBB's page never becomes an empty DTO.
     */
    @Test
    void typedRead_htmlPage200_isStillAnError() {
        reply = new Reply(200, HTML, COOKIE, PAGE, 200);
        PhpbbApiClient api = new PhpbbApiClient(productionClient(), true);
        StepVerifier.create(api.getTopic(1L))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(WebClientResponseException.class)
                        .hasCauseInstanceOf(UnsupportedMediaTypeException.class))
                .verify(WAIT);
        StepVerifier.create(api.listCategories())
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(WebClientResponseException.class)
                        .hasCauseInstanceOf(UnsupportedMediaTypeException.class))
                .verify(WAIT);
    }

    @Test
    void htmlPage_isDrainedOnce_andItsConnectionGoesBackToThePool() {
        ConnectionProvider pool = ConnectionProvider.builder("phpbb-one-connection")
                .maxConnections(1)
                .pendingAcquireTimeout(Duration.ofSeconds(3))
                .build();
        try {
            WebClient web = oneConnectionClient(pool);
            reply = new Reply(503, HTML, COOKIE, PAGE, 200);
            for (int call = 1; call <= 2; call++) {
                StepVerifier.create(post(web))
                        .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(WebClientResponseException.class))
                        .verify(WAIT);
            }
            reply = new Reply(200, JSON, null, "{\"ok\":true}", 0);
            StepVerifier.create(post(web))
                    .assertNext(e -> assertThat(e.getStatusCode().value()).isEqualTo(200))
                    .expectComplete()
                    .verify(WAIT);
        } finally {
            pool.disposeLater().block(WAIT);
        }
    }

    // -------------------------------------------------------------------------
    // The ban seam end to end: PhpbbAdminClient over the production WebClient
    // -------------------------------------------------------------------------

    /** The run-42772063995 shape: phpBB's SQL error page, 503 text/html, body after the headers. */
    @Test
    void ban_phpbbErrorPage_isAuditedWithTheRealStatus() {
        reply = new Reply(503, HTML, COOKIE, PAGE, 200);
        StepVerifier.create(new PhpbbAdminClient(productionClient(), true).suspendUser("sub-1", "spam"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:http-503"))
                .expectComplete()
                .verify(WAIT);
    }

    @Test
    void unban_phpbbErrorPage_isAuditedWithTheRealStatus() {
        reply = new Reply(500, HTML, null, PAGE, 200);
        StepVerifier.create(new PhpbbAdminClient(productionClient(), true).unsuspendUser("sub-1", "appeal"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:http-500"))
                .expectComplete()
                .verify(WAIT);
    }

    /** The extension's own success answer for a ban: 204, no body. */
    @Test
    void ban_extension204_isOk() {
        reply = new Reply(204, null, null, "", 0);
        StepVerifier.create(new PhpbbAdminClient(productionClient(), true).suspendUser("sub-1", "spam"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .expectComplete()
                .verify(WAIT);
    }

    /**
     * PHP sends {@code Content-Type: text/html} by default when a response sets none, so the
     * extension's bare 204 may carry it. A 204 has no content, so it is still the extension's
     * success answer.
     */
    @Test
    void ban_extension204_withPhpsDefaultHtmlContentType_isOk() {
        reply = new Reply(204, HTML, null, "", 0);
        StepVerifier.create(new PhpbbAdminClient(productionClient(), true).suspendUser("sub-1", "spam"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .expectComplete()
                .verify(WAIT);
    }

    /**
     * A 200 text/html page (phpBB's login or board index when the extension route is not
     * there) is not the extension answering. Its body is dropped and its status kept, so
     * without a check here a ban phpBB never applied would be recorded as applied.
     */
    @Test
    void ban_html200Page_isNotOk() {
        reply = new Reply(200, HTML, COOKIE, PAGE, 200);
        StepVerifier.create(new PhpbbAdminClient(productionClient(), true).suspendUser("sub-1", "spam"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:html-200"))
                .expectComplete()
                .verify(WAIT);
    }
}
