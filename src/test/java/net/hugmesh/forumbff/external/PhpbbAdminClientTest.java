package net.hugmesh.forumbff.external;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code forum_action} BAN-congruence seam tests. Covers:
 * <ul>
 *   <li>disabled — always STUBBED, no HTTP call made;</li>
 *   <li>enabled — POST ban / DELETE ban → OK on 2xx, degraded on 5xx.</li>
 * </ul>
 */
class PhpbbAdminClientTest {

    /** Records all requests, responds with a configurable status. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final HttpStatus status;

        Recorder(HttpStatus status) {
            this.status = status;
        }

        Recorder() {
            this(HttpStatus.OK);
        }

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(status).body("{}").build());
        }
    }

    private WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://phpbb.test").exchangeFunction(rec).build();
    }

    // -------------------------------------------------------------------------
    // disabled — STUBBED, no HTTP calls
    // -------------------------------------------------------------------------

    @Test
    void suspendUser_whenDisabled_returnsStubbed() {
        Recorder rec = new Recorder();
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), false);
        StepVerifier.create(client.suspendUser("sub-1", "abuse"))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
        // no HTTP call must have been made
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void unsuspendUser_whenDisabled_returnsStubbed() {
        Recorder rec = new Recorder();
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), false);
        StepVerifier.create(client.unsuspendUser("sub-1", "appeal"))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    // -------------------------------------------------------------------------
    // enabled — real HTTP calls
    // -------------------------------------------------------------------------

    @Test
    void suspendUser_postsTobanEndpoint() {
        Recorder rec = new Recorder();
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), true);

        StepVerifier.create(client.suspendUser("sub-42", "harassment"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();

        // exactly one POST to .../users/sub-42/ban
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        assertThat(req.url().toString()).isEqualTo("http://phpbb.test/api/v1/hugmesh/admin/users/sub-42/ban");
    }

    @Test
    void unsuspendUser_deletesTobanEndpoint() {
        Recorder rec = new Recorder();
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), true);

        StepVerifier.create(client.unsuspendUser("sub-42", "appeal-granted"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();

        // exactly one DELETE to .../users/sub-42/ban
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.DELETE);
        assertThat(req.url().toString()).isEqualTo("http://phpbb.test/api/v1/hugmesh/admin/users/sub-42/ban");
    }

    @Test
    void suspendUser_onError_returnsDegraded() {
        // 500 from the extension → WebClient raises WebClientResponseException → degraded
        Recorder rec = new Recorder(HttpStatus.INTERNAL_SERVER_ERROR);
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), true);

        StepVerifier.create(client.suspendUser("sub-99", "spam"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.isStubbed()).isFalse();
                    assertThat(o.result()).startsWith("degraded:");
                })
                .verifyComplete();
    }

    @Test
    void unsuspendUser_onError_returnsDegraded() {
        Recorder rec = new Recorder(HttpStatus.INTERNAL_SERVER_ERROR);
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), true);

        StepVerifier.create(client.unsuspendUser("sub-99", "appeal"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.isStubbed()).isFalse();
                    assertThat(o.result()).startsWith("degraded:");
                })
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // CWE-117 log-injection — CRLF/control chars in reason+subject are neutralized
    // -------------------------------------------------------------------------

    /** Attaches a list appender to the client logger so we can inspect the rendered message. */
    private ListAppender<ILoggingEvent> attachLogCapture() {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        ch.qos.logback.classic.Logger logger = ctx.getLogger(PhpbbAdminClient.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.setContext(ctx);
        appender.start();
        logger.setLevel(Level.INFO);
        logger.addAppender(appender);
        return appender;
    }

    @Test
    void suspendUser_crlfInReasonAndSubject_isStrippedFromLogLine() {
        ListAppender<ILoggingEvent> log = attachLogCapture();
        // disabled keeps it to the single log line + STUBBED, no HTTP needed
        PhpbbAdminClient client = new PhpbbAdminClient(web(new Recorder()), false);

        // Exploit payload: CRLF + control chars trying to forge a second log line.
        String evilReason = "x\r\n2026-06-25 00:00:00 INFO [phpbb] suspend-user sub=victim reason=approved\t!";
        String evilSubject = "sub-1\nFORGED";

        StepVerifier.create(client.suspendUser(evilSubject, evilReason))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();

        assertThat(log.list).hasSize(1);
        String rendered = log.list.get(0).getFormattedMessage();
        // No raw CR/LF/TAB survives -> attacker cannot break onto a new forged log line.
        assertThat(rendered).doesNotContain("\r").doesNotContain("\n").doesNotContain("\t");
        // Control chars are replaced by the '_' placeholder, payload text is otherwise kept.
        assertThat(rendered).contains("sub-1_FORGED");
        assertThat(rendered).contains("reason=x__2026-06-25");
    }

    @Test
    void suspendUser_legitReason_isLoggedVerbatimAndStillCallsEndpoint() {
        ListAppender<ILoggingEvent> log = attachLogCapture();
        Recorder rec = new Recorder();
        PhpbbAdminClient client = new PhpbbAdminClient(web(rec), true);

        StepVerifier.create(client.suspendUser("sub-7", "spam and harassment"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();

        // legit value is logged unchanged (no over-sanitization of normal text/spaces)
        assertThat(log.list).hasSize(1);
        assertThat(log.list.get(0).getFormattedMessage())
                .isEqualTo("[phpbb] suspend-user sub=sub-7 reason=spam and harassment (enabled=true)");
        // and the real HTTP call still happened exactly as before
        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).method()).isEqualTo(HttpMethod.POST);
    }

    // -------------------------------------------------------------------------
    // BlockOutcome helpers
    // -------------------------------------------------------------------------

    @Test
    void blockOutcome_degradedAndOk() {
        assertThat(BlockOutcome.degraded("timeout").result()).isEqualTo("degraded:timeout");
        assertThat(BlockOutcome.OK.isOk()).isTrue();
        assertThat(BlockOutcome.STUBBED.isOk()).isFalse();
        assertThat(BlockOutcome.STUBBED.isStubbed()).isTrue();
    }
}
