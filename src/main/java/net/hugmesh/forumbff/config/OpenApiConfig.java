package net.hugmesh.forumbff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
