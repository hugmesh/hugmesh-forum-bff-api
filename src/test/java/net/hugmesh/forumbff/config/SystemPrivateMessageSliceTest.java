package net.hugmesh.forumbff.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.forumbff.forum.SystemPrivateMessageController;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;
import net.hugmesh.forumbff.testsupport.TestIssuer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code POST /bff/forum/system/private-messages} end to end through the REAL production
 * filter chain ({@link SecurityConfig}, real RS256 tokens from {@link TestIssuer}), the real
 * {@link SystemPrivateMessageController} and the real {@link PhpbbApiClient}, against an
 * in-JVM fake of the forum-api extension route. Proves the path rule (ROLE_SYSTEM only), the
 * forward (same bearer, same Idempotency-Key, same three body fields) and the answer mapping
 * that admin-bff's {@code ForumSystemPmClient} depends on. The fake is not phpBB: nothing
 * here was run against a real extension.
 */
class SystemPrivateMessageSliceTest extends SecuritySliceSupport {

    private static final String PATH = "/bff/forum/system/private-messages";
    private static final String BODY = "{\"recipient\":\"hugmesh/alice\",\"subject\":\"Title\",\"text\":\"Body\"}";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    record Seen(String method, String path, String authorization, String hugmeshJwt, String idemKey, JsonNode body) { }

    private TestIssuer issuer;
    /** A second trusted issuer: it puts the registry in multi-issuer mode, so the chain
     *  authenticates through the real per-issuer resolver (the single-issuer path needs a
     *  ReactiveJwtDecoder bean a slice does not have). */
    private TestIssuer otherDomain;
    private HttpServer forumApi;
    private final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());
    private volatile int replyStatus = 200;
    private volatile String replyBody = "{\"id\":901}";
    private volatile String replyContentType = "application/json";
    private volatile boolean replyReplayed = false;
    private WebTestClient client;
    private WebTestClient darkClient;

    @BeforeEach
    void setUp() throws IOException {
        issuer = new TestIssuer();
        otherDomain = new TestIssuer();
        forumApi = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        forumApi.createContext("/", this::handle);
        forumApi.start();

        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + otherDomain.issuerUri() + "=brandy");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(new TenancyResourceServerConfig(registry, "", "", false, 600000L));
        WebClient http = WebClient.builder()
                .baseUrl("http://127.0.0.1:" + forumApi.getAddress().getPort()).build();
        client = sliceClient(registry, provider(resolver),
                new SystemPrivateMessageController(new PhpbbApiClient(http, true)));
        darkClient = sliceClient(registry, provider(resolver),
                new SystemPrivateMessageController(new PhpbbApiClient(http, false)));
    }

    @AfterEach
    void tearDown() {
        forumApi.stop(0);
        issuer.close();
        otherDomain.close();
    }

    private void handle(HttpExchange ex) throws IOException {
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        seen.add(new Seen(ex.getRequestMethod(), ex.getRequestURI().getPath(),
                ex.getRequestHeaders().getFirst("Authorization"),
                ex.getRequestHeaders().getFirst("X-HugMesh-JWT"),
                ex.getRequestHeaders().getFirst("Idempotency-Key"),
                raw.isBlank() ? null : MAPPER.readTree(raw)));
        byte[] b = replyBody.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", replyContentType);
        if (replyReplayed) {
            ex.getResponseHeaders().add("Idempotent-Replayed", "true");
        }
        ex.sendResponseHeaders(replyStatus, b.length == 0 ? -1 : b.length);
        if (b.length > 0) {
            ex.getResponseBody().write(b);
        }
        ex.close();
    }

    private String token(String... roles) {
        return issuer.mint("system-sub", List.of(roles));
    }

    private WebTestClient.ResponseSpec post(WebTestClient c, String bearer, String key, String body) {
        return c.post().uri(PATH)
                .headers(h -> {
                    if (bearer != null) {
                        h.setBearerAuth(bearer);
                    }
                    if (key != null) {
                        h.set("Idempotency-Key", key);
                    }
                })
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    // ── the forward ─────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"system", "ROLE_SYSTEM"})
    void systemToken_isForwardedWithTheSameBearerKeyAndBody_and200PassesThrough(String role) {
        String tok = token("user", role);

        post(client, tok, "hm-row-1", BODY)
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectHeader().doesNotExist("Idempotent-Replayed")
                .expectBody(String.class).isEqualTo("{\"id\":901}");

        assertThat(seen).hasSize(1);
        Seen s = seen.get(0);
        assertThat(s.method() + " " + s.path()).isEqualTo("POST /api/v1/hugmesh/system/private-messages");
        assertThat(s.authorization()).isEqualTo("Bearer " + tok);
        assertThat(s.hugmeshJwt()).isEqualTo(tok);
        assertThat(s.idemKey()).isEqualTo("hm-row-1");
        assertThat(s.body().get("recipient").asText()).isEqualTo("hugmesh/alice");
        assertThat(s.body().get("subject").asText()).isEqualTo("Title");
        assertThat(s.body().get("text").asText()).isEqualTo("Body");
        assertThat(s.body().size()).isEqualTo(3);
    }

    @Test
    void aReplayedKey_passesTheReplayHeaderThrough() {
        replyReplayed = true;
        post(client, token("system"), "hm-row-1", BODY)
                .expectStatus().isOk()
                .expectHeader().valueEquals("Idempotent-Replayed", "true")
                .expectBody(String.class).isEqualTo("{\"id\":901}");
    }

    // ── answer mapping ──────────────────────────────────────────────────────

    @Test
    void unknownRecipient404_isMappedVerbatim() {
        replyStatus = 404;
        replyBody = "{\"code\":\"unknown_recipient\"}";
        post(client, token("system"), "k", BODY)
                .expectStatus().isNotFound()
                .expectBody(String.class).isEqualTo("{\"code\":\"unknown_recipient\"}");
    }

    @Test
    void any404WithoutTheRecipientCode_becomes502_neverA404() {
        // A missing extension route must stay a RETRY for admin-bff, not a terminal skip.
        for (String body : new String[] {"{\"error\":true,\"status\":404,\"message\":\"Not Found\"}",
                "{\"code\":\"forum_disabled\"}", ""}) {
            replyStatus = 404;
            replyBody = body;
            post(client, token("system"), "k", BODY)
                    .expectStatus().isEqualTo(502)
                    .expectBody(String.class).isEqualTo("{\"code\":\"forum_upstream_error\"}");
        }
    }

    @Test
    void idempotencyCodes_passThrough() {
        replyStatus = 422;
        replyBody = "{\"code\":\"idempotency_key_reused\"}";
        post(client, token("system"), "k", BODY)
                .expectStatus().isEqualTo(422)
                .expectBody(String.class).isEqualTo("{\"code\":\"idempotency_key_reused\"}");

        replyStatus = 409;
        replyBody = "{\"code\":\"idempotency_in_progress\"}";
        post(client, token("system"), "k", BODY)
                .expectStatus().isEqualTo(409)
                .expectBody(String.class).isEqualTo("{\"code\":\"idempotency_in_progress\"}");
    }

    @Test
    void upstreamErrors_become502() {
        for (int status : new int[] {400, 401, 403, 500, 503}) {
            replyStatus = status;
            replyBody = "{\"error\":true,\"status\":" + status + "}";
            post(client, token("system"), "k", BODY).expectStatus().isEqualTo(502);
        }
    }

    @Test
    void a2xxWithoutTheDocumentedBody_isNotReportedAsSent() {
        // e.g. a phpBB page served instead of the extension route: never a false "sent".
        replyStatus = 200;
        replyContentType = "text/html";
        replyBody = "<html>board index</html>";
        post(client, token("system"), "k", BODY).expectStatus().isEqualTo(502);

        replyContentType = "application/json";
        replyBody = "{}";
        post(client, token("system"), "k", BODY).expectStatus().isEqualTo(502);
    }

    @Test
    void extensionDown_is502() {
        forumApi.stop(0);
        post(client, token("system"), "k", BODY)
                .expectStatus().isEqualTo(502)
                .expectBody(String.class).isEqualTo("{\"code\":\"forum_upstream_error\"}");
    }

    @Test
    void phpbbDark_is503_andNothingIsForwarded() {
        post(darkClient, token("system"), "k", BODY)
                .expectStatus().isEqualTo(503)
                .expectBody(String.class).isEqualTo("{\"code\":\"forum_unavailable\"}");
        assertThat(seen).isEmpty();
    }

    // ── who may call it ─────────────────────────────────────────────────────

    @Test
    void noToken_is401_andNothingIsForwarded() {
        post(client, null, "k", BODY).expectStatus().isUnauthorized();
        assertThat(seen).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"user", "forum", "mod", "admin", "superadmin", "service", "ROLE_SERVICE",
            "matrix", "mastodon", "systems", "sys"})
    void everyNonSystemRole_is403_andNothingIsForwarded(String role) {
        post(client, token("user", role), "k", BODY).expectStatus().isForbidden();
        assertThat(seen).isEmpty();
    }

    @Test
    void theSystemRoleViaPermissions_isNotTheRole() {
        // permissions entries starting ROLE_ are dropped by CasdoorAuthorities; a bare
        // "SYSTEM" permission is an authority named SYSTEM, not ROLE_SYSTEM.
        String tok = issuer.mintWithClaims("system-sub", java.util.Map.of(
                "roles", List.of("user"), "permissions", List.of("ROLE_SYSTEM", "SYSTEM")));
        post(client, tok, "k", BODY).expectStatus().isForbidden();
        assertThat(seen).isEmpty();
    }

    // ── request validation ──────────────────────────────────────────────────

    @Test
    void missingOrBadIdempotencyKey_is400_andNothingIsForwarded() {
        post(client, token("system"), null, BODY).expectStatus().isBadRequest();
        post(client, token("system"), "has space", BODY).expectStatus().isBadRequest();
        post(client, token("system"), "k".repeat(256), BODY).expectStatus().isBadRequest();
        assertThat(seen).isEmpty();
    }

    @Test
    void blankRecipient_is400_andNothingIsForwarded() {
        post(client, token("system"), "k", "{\"recipient\":\"  \",\"subject\":\"T\",\"text\":\"B\"}")
                .expectStatus().isBadRequest();
        assertThat(seen).isEmpty();
    }
}
