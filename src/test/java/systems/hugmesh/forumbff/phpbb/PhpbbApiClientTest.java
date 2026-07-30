package systems.hugmesh.forumbff.phpbb;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.forumbff.forum.ForumDto;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The headless phpBB seam (the design-chosen {@code hugmesh/forum-api} extension
 * client). GATED stub-seam contract: when {@code phpbb.enabled=false} (the default),
 * reads return typed empty/degraded and writes are no-ops — and NO HTTP call is made
 * (the recording exchange function stays empty). When enabled, the real URIs are hit.
 * Mirrors the mod-bff {@code ExternalAdminClientTest} "wired client + stubbed call"
 * pattern.
 */
class PhpbbApiClientTest {

    /** Records any outgoing request — should stay EMPTY while the seam is stubbed. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body("[]").build());
        }
    }

    private WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://phpbb.test").exchangeFunction(rec).build();
    }

    @Test
    void listCategories_disabled_isEmpty_noHttpCall() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), false);
        StepVerifier.create(client.listCategories()).verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void stats_disabled_isDegraded_noHttpCall() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), false);
        StepVerifier.create(client.stats())
                .assertNext(s -> assertThat(s.source()).isEqualTo("degraded"))
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void createTopic_disabled_isEmpty_noHttpCall() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), false);
        StepVerifier.create(client.createTopic(new ForumDto.CreateTopic(1, "t", "b"))).verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void setUserGroups_disabled_isNoop_noHttpCall() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), false);
        ForumDto.GroupAssignment a = new ForumDto.GroupAssignment("sub-1",
                systems.hugmesh.forumbff.forum.ForumGroup.REGISTERED, List.of("ROLE_FORUM"), java.time.Instant.now());
        StepVerifier.create(client.setUserGroups(a)).verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void listCategories_enabled_hitsExtensionUri() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), true);
        StepVerifier.create(client.listCategories()).verifyComplete();
        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).url().getPath()).isEqualTo("/api/v1/hugmesh/categories");
    }

    @Test
    void getPost_disabled_isEmpty_noHttpCall() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), false);
        StepVerifier.create(client.getPost(7L)).verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void getPost_enabled_hitsPostUri_notTopicUri() {
        Recorder rec = new Recorder();
        PhpbbApiClient client = new PhpbbApiClient(web(rec), true);
        // Body shape is irrelevant here — we only assert the ownership resolve hits the POST
        // URI (/posts/{id}), NOT the same-id topic. (No @CircuitBreaker proxy in this plain
        // unit test, so swallow any body-deserialization error to isolate the URI assertion.)
        StepVerifier.create(client.getPost(7L).onErrorResume(e -> Mono.empty())).verifyComplete();
        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).url().getPath()).isEqualTo("/api/v1/hugmesh/posts/7");
    }
}
