package net.hugmesh.forumbff.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import net.hugmesh.forumbff.forum.ForumAction;
import net.hugmesh.forumbff.forum.ForumDto;
import net.hugmesh.forumbff.forum.ForumUserRole;

/**
 * GraalVM native-image / AOT reachability hints for the bits the static analyzer
 * cannot see through on its own — mirrors hugmesh-user-bff-api / federation-api
 * {@code NativeHintsConfig}.
 *
 * <p>Spring Boot's own AOT processing covers the framework surface (the WebFlux
 * WebClient codecs, the reactive OAuth2 resource-server JWT pipeline, R2DBC, and
 * the Jackson auto-configuration). What it cannot always infer:
 *
 * <ul>
 *   <li><b>JSON-bound DTOs</b> reached reflectively through Jackson — the records
 *       crossing the HTTP / phpBB-extension boundary ({@link ForumDto} nested records,
 *       {@link ForumAction}, {@link ForumUserRole}). They need explicit binding hints
 *       so their canonical constructors/accessors survive native image.</li>
 *   <li><b>The springdoc Swagger UI webjar resources</b> — native-image strips
 *       classpath resources by default; the bundled assets 404 without an explicit
 *       resource-include pattern. The raw {@code /v3/api-docs} JSON (what ng-openapi-gen
 *       + the docs pipeline consume) is bean-produced and unaffected.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(NativeHintsConfig.Hints.class)
public class NativeHintsConfig {

    static class Hints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection()
                    .registerType(ForumDto.Category.class, dtoCategories())
                    .registerType(ForumDto.Topic.class, dtoCategories())
                    .registerType(ForumDto.Reply.class, dtoCategories())
                    .registerType(ForumDto.ForumUser.class, dtoCategories())
                    .registerType(ForumDto.Stats.class, dtoCategories())
                    .registerType(ForumDto.CreateTopic.class, dtoCategories())
                    .registerType(ForumDto.CreateReply.class, dtoCategories())
                    .registerType(ForumDto.EditPost.class, dtoCategories())
                    .registerType(ForumDto.ModerationAction.class, dtoCategories())
                    .registerType(ForumDto.GroupAssignment.class, dtoCategories())
                    .registerType(ForumAction.class, dtoCategories())
                    .registerType(ForumUserRole.class, dtoCategories());

            hints.resources()
                    .registerPattern("META-INF/resources/webjars/swagger-ui/*")
                    .registerPattern("META-INF/resources/webjars/swagger-ui/**");
        }

        private static MemberCategory[] dtoCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
                    MemberCategory.ACCESS_DECLARED_FIELDS,
            };
        }
    }
}
