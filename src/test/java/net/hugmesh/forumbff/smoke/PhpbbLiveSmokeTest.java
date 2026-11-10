package net.hugmesh.forumbff.smoke;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.forumbff.forum.ForumAction;
import net.hugmesh.forumbff.forum.ForumActionRepository;
import net.hugmesh.forumbff.forum.ForumActionVerb;
import net.hugmesh.forumbff.testsupport.TestIssuer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * LIVE phpBB smoke test: this BFF against a REAL, throwaway phpBB 3.3.11 running the
 * {@code hugmesh/forumapi} extension (hugmesh-forum-bff-api#1).
 *
 * <p>Every other test in this repo stubs or mocks the phpBB leg. This one boots the
 * real image, lets its entrypoint run the headless install against an empty Postgres
 * and enable the extension, and then drives this BFF's own HTTP surface with both
 * seams ON ({@code phpbb.enabled=true}, {@code external.forum.enabled=true}):
 * <ul>
 *   <li>{@code GET /bff/forum/categories} and {@code GET /bff/forum/topics} return the
 *       rows a fresh phpBB install ships ("Your first forum", "Welcome to phpBB3");</li>
 *   <li>{@code POST /bff/forum/topics} creates a topic that phpBB then lists;</li>
 *   <li>{@code POST /bff/forum/admin/users/{sub}/ban} makes the real admin call
 *       ({@code PhpbbAdminClient.doSuspend}) and answers 200 {@code applied} /
 *       {@code external=ok} — and phpBB's own tables show the ban.</li>
 * </ul>
 *
 * <h3>Which phpBB image</h3>
 * The generator's {@code PHPBB=1} compose profile
 * ({@code hugmesh-generator/tests/stack/compose.alt-social.yaml}) builds hugmesh-forum-api's
 * Dockerfile: official phpBB 3.3.11 plus the extension. Upstream phpBB ships no usable
 * image. This test does not build anything: it pulls the image that same Dockerfile
 * produced and the forum-api release workflow published, pinned by DIGEST so the bytes
 * can never move under it. Tag {@code 0.4.0-beta.2} / {@code sha-d2821bd0978e}.
 * The env below mirrors that compose service (DB alias {@code db}, the extension's own
 * {@code docker/install-config.compose.yml}, the dev-only plain-http JWKS knob).
 *
 * <h3>Auth</h3>
 * A {@link TestIssuer} signs the JWTs. The BFF validates them through
 * {@code jwk-set-uri}; the BFF forwards them to phpBB, and the extension validates them
 * again against the SAME JWKS, reached from inside the container through Testcontainers'
 * host tunnel ({@code host.testcontainers.internal}). The extension compares {@code iss}
 * as a plain string, so its expected issuer is the issuer URI the tokens carry.
 *
 * <h3>Not part of the plain unit run</h3>
 * Tagged {@value #TAG}. The pom's surefire config excludes the tag by default; the
 * {@code phpbb-smoke} Maven profile runs ONLY this tag ({@code ./mvnw test -Pphpbb-smoke}).
 * It needs Docker, and it fails rather than skipping when Docker is absent.
 */
@Tag(PhpbbLiveSmokeTest.TAG)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient(timeout = "PT60S")
@ActiveProfiles("test")
class PhpbbLiveSmokeTest extends PostgresTestSupport {

    static final String TAG = "phpbb-smoke";

    /**
     * hugmesh-forum-api 0.4.0-beta.2 (sha-d2821bd0978e): phpBB 3.3.11 + hugmesh/forumapi.
     * {@code -Dphpbb.smoke.image=<ref>} runs against another build of the same image (a
     * newer forum-api release, or one built locally from that repo's Dockerfile).
     */
    static final String PHPBB_IMAGE = System.getProperty("phpbb.smoke.image",
            "ghcr.io/hugmesh/hugmesh-forum-api@sha256:0ebe0183fb5eeb55e6779fb9cb20a2bc19a2b1316abe1d565faf5a0ab31623ac");

    /** Same Postgres the generator's phpbb-db service runs. */
    static final String PHPBB_DB_IMAGE = "postgres:16-alpine";

    /** Throwaway, container-local credentials, identical to the extension's compose install YAML. */
    private static final String DB_NAME = "phpbb";
    private static final String DB_USER = "phpbb";
    private static final String DB_PASS = "phpbb";

    /** phpBB's fresh install: forum 2 "Your first forum", holding topic "Welcome to phpBB3". */
    private static final long FIRST_FORUM_ID = 2L;

    private static TestIssuer issuer;
    private static Network network;
    private static GenericContainer<?> phpbbDb;
    private static GenericContainer<?> phpbb;

    @SuppressWarnings("resource")
    private static synchronized void startPhpbb() {
        if (phpbb != null) {
            return;
        }
        issuer = new TestIssuer();
        int issuerPort = URI.create(issuer.issuerUri()).getPort();
        // Must happen BEFORE the phpBB container starts: it opens the tunnel that
        // host.testcontainers.internal:<port> resolves through.
        Testcontainers.exposeHostPorts(issuerPort);

        network = Network.newNetwork();
        phpbbDb = new GenericContainer<>(DockerImageName.parse(PHPBB_DB_IMAGE))
                .withNetwork(network)
                // The extension's install YAML hard-codes `dbhost: db` (the generator
                // aliases its phpbb-db service the same way).
                .withNetworkAliases("db", "phpbb-db")
                .withEnv("POSTGRES_DB", DB_NAME)
                .withEnv("POSTGRES_USER", DB_USER)
                .withEnv("POSTGRES_PASSWORD", DB_PASS)
                .withExposedPorts(5432)
                .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*\\s", 2)
                        .withStartupTimeout(Duration.ofMinutes(2)));
        phpbbDb.start();

        phpbb = new GenericContainer<>(DockerImageName.parse(PHPBB_IMAGE))
                .withNetwork(network)
                .withAccessToHost(true)
                .withEnv("PHPBB_DB_HOST", "db")
                .withEnv("PHPBB_DB_PORT", "5432")
                .withEnv("PHPBB_DB_NAME", DB_NAME)
                .withEnv("PHPBB_DB_USER", DB_USER)
                .withEnv("PHPBB_APP_PASSWORD", DB_PASS)
                .withEnv("PHPBB_TABLE_PREFIX", "phpbb_")
                .withEnv("PHPBB_INSTALL_CONFIG",
                        "/var/www/html/ext/hugmesh/forumapi/docker/install-config.compose.yml")
                .withEnv("HUGMESH_JWKS_URI",
                        "http://host.testcontainers.internal:" + issuerPort + "/.well-known/jwks.json")
                // The extension's default-off dev knob: permits an http:// JWKS (the
                // in-process issuer has no TLS). Never set in a cluster.
                .withEnv("HUGMESH_JWKS_ALLOW_INSECURE_HTTP", "1")
                .withEnv("HUGMESH_JWT_ISSUER", issuer.issuerUri())
                .withExposedPorts(8080)
                // /health answers 200 only once install/ is gone and the extension routes.
                .waitingFor(Wait.forHttp("/api/v1/hugmesh/health").forPort(8080).forStatusCode(200)
                        .withStartupTimeout(Duration.ofMinutes(5)));
        phpbb.start();
    }

    @DynamicPropertySource
    static void livePhpbb(DynamicPropertyRegistry registry) {
        startPhpbb();
        TestIssuer.registerAsBackCompatIssuer(registry, issuer);
        registry.add("phpbb.enabled", () -> "true");
        registry.add("external.forum.enabled", () -> "true");
        registry.add("phpbb.api.base-url",
                () -> "http://" + phpbb.getHost() + ":" + phpbb.getMappedPort(8080));
    }

    @AfterAll
    static void stopPhpbb() {
        if (phpbb != null) phpbb.stop();
        if (phpbbDb != null) phpbbDb.stop();
        if (network != null) network.close();
        if (issuer != null) issuer.close();
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired WebTestClient web;
    @Autowired ForumActionRepository audit;

    /** Decode a response body with Jackson 2 directly, independent of the codec Boot picks. */
    private static JsonNode json(String body) {
        assertThat(body).as("response body").isNotNull();
        try {
            return JSON.readTree(body);
        } catch (JsonProcessingException e) {
            throw new AssertionError("response body is not JSON: " + body, e);
        }
    }

    private static String forumUser(String subject) {
        return issuer.mint(subject, List.of("forum"));
    }

    private static String admin(String subject) {
        return issuer.mint(subject, List.of("admin", "forum"));
    }

    private JsonNode get(String uri, String token) {
        JsonNode body = json(web.get().uri(uri)
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).returnResult().getResponseBody());
        assertThat(body).as("GET %s body", uri).isNotNull();
        return body;
    }

    private static List<String> titles(JsonNode topicsResponse) {
        List<String> out = new ArrayList<>();
        topicsResponse.path("topics").forEach(t -> out.add(t.path("title").asText()));
        return out;
    }

    private JsonNode createTopic(String token, String title) {
        JsonNode body = json(web.post().uri("/bff/forum/topics")
                .headers(h -> h.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("categoryId", FIRST_FORUM_ID, "title", title,
                        "body", "Posted through hugmesh-forum-bff-api by the live smoke test."))
                .exchange()
                // 200 = phpBB created it. A 202 here would mean the BFF fell back to its
                // pending/stub path, i.e. nothing reached phpBB.
                .expectStatus().isOk()
                .expectBody(String.class).returnResult().getResponseBody());
        assertThat(body).isNotNull();
        return body.path("topic");
    }

    @Test
    void categories_returnTheRealPhpbbForums() {
        JsonNode categories = get("/bff/forum/categories", forumUser("smoke-reader-" + UUID.randomUUID()))
                .path("categories");

        assertThat(categories.isArray()).isTrue();
        assertThat(categories.size()).as("a fresh phpBB install has one postable forum").isGreaterThanOrEqualTo(1);
        List<String> names = new ArrayList<>();
        categories.forEach(c -> names.add(c.path("name").asText()));
        assertThat(names).contains("Your first forum");
    }

    @Test
    void topics_returnTheRealPhpbbTopics() {
        JsonNode topics = get("/bff/forum/topics?categoryId=" + FIRST_FORUM_ID,
                forumUser("smoke-reader-" + UUID.randomUUID()));

        assertThat(titles(topics)).as("phpBB's install seeds one welcome topic in forum 2")
                .contains("Welcome to phpBB3");
    }

    @Test
    void createTopic_isWrittenToPhpbb_andPhpbbThenListsIt() throws SQLException {
        String subject = "smoke-poster-" + UUID.randomUUID();
        String title = "Live smoke topic " + UUID.randomUUID();

        JsonNode topic = createTopic(forumUser(subject), title);
        assertThat(topic.path("id").asLong()).as("phpBB assigned a topic id").isPositive();
        assertThat(topic.path("title").asText()).isEqualTo(title);
        assertThat(topic.path("authorSubject").asText()).isEqualTo(subject);

        // A second, unrelated reader sees it through phpBB's own listing.
        JsonNode listed = get("/bff/forum/topics?categoryId=" + topic.path("categoryId").asLong(),
                forumUser("smoke-reader-" + UUID.randomUUID()));
        assertThat(titles(listed)).contains(title);

        // And the row is really in phpBB's database, not just echoed by the BFF.
        assertThat(count("SELECT COUNT(*) FROM phpbb_topics WHERE topic_title = ?", title)).isEqualTo(1);
    }

    @Test
    void suspend_makesTheRealAdminCall_andReturnsOk() throws SQLException {
        // The extension 404s a ban for a subject it has never mapped, so the target
        // first becomes a phpBB user the normal way: by posting.
        String target = "smoke-banned-" + UUID.randomUUID();
        createTopic(forumUser(target), "Topic before the ban " + UUID.randomUUID());
        assertThat(bansFor(target)).as("not banned yet").isZero();

        EntityExchangeResult<String> result = web.post().uri("/bff/forum/admin/users/{subject}/ban", target)
                .headers(h -> h.setBearerAuth(admin("smoke-admin-" + UUID.randomUUID())))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("reason", "live smoke test"))
                .exchange()
                .expectBody(String.class).returnResult();
        JsonNode outcome = json(result.getResponseBody());
        String external = outcome.path("external").asText();

        // Audited whatever phpBB answered (the README's "always audited" contract).
        List<ForumAction> audited = audit.list(null)
                .filter(a -> target.equals(a.target()) && ForumActionVerb.USER_BAN.token().equals(a.action()))
                .collectList().block(Duration.ofSeconds(30));
        assertThat(audited).as("forum_action rows for the ban").hasSize(1);
        assertThat(audited.get(0).outcome()).isEqualTo(external);

        // 200 only for BlockOutcome.OK. STUBBED or degraded answer 202 pending-reconcile;
        // the body is in the message so a red run names what phpBB answered.
        assertThat(result.getStatus().value()).as("ban status, body=%s", result.getResponseBody()).isEqualTo(200);
        assertThat(external).as("BlockOutcome").isEqualTo("ok");
        assertThat(outcome.path("state").asText()).isEqualTo("applied");

        // phpBB's own tables carry the ban: a banlist row and user_type = USER_IGNORE (3).
        assertThat(bansFor(target)).isEqualTo(1);
        assertThat(count("SELECT COUNT(*) FROM phpbb_users u JOIN phpbb_hugmesh_casdoor_map m "
                + "ON m.user_id = u.user_id WHERE m.casdoor_sub = ? AND u.user_type = 3", target)).isEqualTo(1);
    }

    private static int bansFor(String subject) throws SQLException {
        return count("SELECT COUNT(*) FROM phpbb_banlist b JOIN phpbb_hugmesh_casdoor_map m "
                + "ON m.user_id = b.ban_userid WHERE m.casdoor_sub = ?", subject);
    }

    private static int count(String sql, String param) throws SQLException {
        String url = "jdbc:postgresql://" + phpbbDb.getHost() + ":" + phpbbDb.getMappedPort(5432) + "/" + DB_NAME;
        try (Connection c = DriverManager.getConnection(url, DB_USER, DB_PASS);
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }
}
