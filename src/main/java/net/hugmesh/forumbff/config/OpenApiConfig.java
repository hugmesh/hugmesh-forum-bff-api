package net.hugmesh.forumbff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Minimal OpenAPI document metadata for the forum BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed client for the paired hugmesh-forum-ui and the docs
 * pipeline key off these fields. A programmatic {@link OpenAPI} bean is used
 * (rather than the {@code @OpenAPIDefinition} annotation) so the metadata is plain
 * bean wiring — no annotation reflection scan, which keeps the GraalVM native
 * build hint surface minimal.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI forumBffOpenApi() {
        return new OpenAPI()
                // Pin an empty-URL server so the dumped spec is DETERMINISTIC. Under Boot 4 /
                // springdoc 3.x the auto-generated "Generated server url" resolves to the live
                // request host:port — which is a RANDOM_PORT in the OpenApiSpecDumpTest, so the
                // committed spec would otherwise carry a per-run port (e.g. http://localhost:42077).
                // Boot 3.5 / springdoc 2.x emitted "" here; pin it to keep the byte-stable artefact.
                // An empty URL also means same-origin, which is correct for a BFF behind the
                // fe-gateway — the absolute localhost URL pointed generated clients at a dead port.
                .servers(List.of(new Server().url("")))
                .info(new Info()
                        .title("hugmesh-forum-bff-api")
                        .version("0.1.0")
                        .description("Forum BFF API (/bff/forum/**) — the single browser->phpBB path "
                                + "wrapping the headless phpBB forum per role + action: authenticated "
                                + "read/post under /bff/forum/**, MOD+FORUM moderation under "
                                + "/bff/forum/moderation/**, and the ADMIN console seam under "
                                + "/bff/forum/admin/**. phpBB has no native REST API; the headless "
                                + "hugmesh/forum-api extension client is a gated stub-seam."));
    }
}
