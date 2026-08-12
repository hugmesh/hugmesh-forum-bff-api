package net.hugmesh.forumbff.external;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link PhpbbAdminClient} (the {@code forum_action} BAN congruence seam)
 * on the JWT-forwarding + hygiene-filtered phpBB {@link WebClient} (the same
 * {@code phpbbWebClient} bean {@link net.hugmesh.forumbff.phpbb.PhpbbApiClient}
 * uses). MIRRORS the hugmesh-mod-bff-api {@code ExternalAdminConfig}: the
 * {@code external.forum.enabled} flag defaults FALSE so a phpbb-less dev/test run boots
 * clean (the client short-circuits to {@link BlockOutcome#STUBBED} with no HTTP call);
 * when true, {@code doSuspend} makes the real HTTP call against the confirmed phpBB
 * extension admin API shape — see the client javadoc + README.
 */
@Configuration(proxyBeanMethods = false)
public class ExternalForumConfig {

    @Bean
    PhpbbAdminClient phpbbAdminClient(
            @Qualifier("phpbbWebClient") WebClient phpbbWebClient,
            @Value("${external.forum.enabled:false}") boolean enabled) {
        return new PhpbbAdminClient(phpbbWebClient, enabled);
    }
}
