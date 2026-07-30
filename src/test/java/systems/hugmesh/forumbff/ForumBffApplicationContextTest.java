package systems.hugmesh.forumbff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;

/**
 * Context-load smoke test: the full Spring context boots under the {@code test}
 * profile. The DB is a REAL Testcontainers Postgres wired by
 * {@link PostgresTestSupport} (the shared commons base auto-registers the r2dbc URL +
 * the Liquibase JDBC URL onto a fresh per-class database), so Liquibase migrates the
 * schema the repositories + r2dbc-converters then wire over. The phpBB extension call
 * + the ban congruence stay stubbed and the reactive JWT decoder is mocked so no live
 * Casdoor issuer is contacted. This proves all controllers, services, repositories,
 * the phpBB clients, and the security + native-hints config wire together.
 */
@SpringBootTest
@ActiveProfiles("test")
class ForumBffApplicationContextTest extends PostgresTestSupport {

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the
     *  oauth2 resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void contextLoads() {
        // success = the application context started with every bean wired.
    }
}
