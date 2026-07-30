package systems.hugmesh.forumbff.external;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Reactive admin client for the phpBB extension's ADMIN-scoped ban/suspend endpoints
 * — the {@code forum_action} BAN congruence seam. MIRRORS the hugmesh-mod-bff-api
 * {@code MastodonAdminClient} stub-seam EXACTLY (we do NOT touch mod-bff).
 *
 * <h3>Ban-by-role-removal congruence</h3>
 * Removing the forum role from a user (in Casdoor, or via admin-bff
 * {@code POST /bff/admin/forum/users/{id}/ban}) makes the gateway deny the forum
 * surface on the next route-access refresh. This client carries that congruence INTO
 * phpBB: {@link #suspendUser} hits the extension's ADMIN endpoint which (i) issues a
 * phpBB user ban, (ii) removes the user from REGISTERED/GLOBAL_MODERATORS, and (iii)
 * deletes the user's {@code phpbb_sessions} rows. {@link #unsuspendUser} reverses it
 * (re-add groups per current roles). Both are written to the OWN {@code forum_action}
 * table by the caller regardless of the outcome, so a stubbed ban is still auditable.
 *
 * <h3>Real HTTP calls — stub replaced with real call</h3>
 * The phpBB extension admin shape is confirmed; {@link #doSuspend} now makes the real
 * HTTP call:
 * <ul>
 *   <li>when {@code external.forum.enabled=false} — returns {@link BlockOutcome#STUBBED}
 *       without any HTTP call (safe default);</li>
 *   <li>when {@code external.forum.enabled=true} — calls the extension admin API and
 *       returns {@link BlockOutcome#OK} on 2xx or {@link BlockOutcome#degraded(String)}
 *       on error.</li>
 * </ul>
 * Wrapped in {@code @CircuitBreaker(name="phpbb-admin")}: a stalled/erroring extension
 * trips the breaker and the {@link #suspendFallback fallback} returns {@code degraded}
 * — NEVER {@link BlockOutcome#OK} — so the caller returns 202 pending-reconcile.
 */
public class PhpbbAdminClient {

    private static final Logger log = LoggerFactory.getLogger(PhpbbAdminClient.class);

    private static final String BASE = "/api/v1/hugmesh/admin";

    private final WebClient http;
    private final boolean enabled;

    public PhpbbAdminClient(WebClient http, boolean enabled) {
        this.http = http;
        this.enabled = enabled;
    }

    public boolean isEnabled() { return enabled; }

    /**
     * Suspend/ban a user in phpBB, keyed by Casdoor {@code sub} (the immutable identity
     * — NOT localpart). The congruence of removing the forum role. Breaker-guarded.
     */
    @CircuitBreaker(name = "phpbb-admin", fallbackMethod = "suspendFallback")
    public Mono<BlockOutcome> suspendUser(String casdoorSubject, String reason) {
        // CWE-117: neutralize CR/LF + control chars in caller-supplied values BEFORE
        // they reach the log line so a crafted reason/subject cannot forge log entries.
        log.info("[phpbb] suspend-user sub={} reason={} (enabled={})", forLog(casdoorSubject), forLog(reason), enabled);
        return doSuspend(casdoorSubject, reason, true);
    }

    /** Lift a previously applied phpBB ban + re-add groups per the user's CURRENT roles. Breaker-guarded. */
    @CircuitBreaker(name = "phpbb-admin", fallbackMethod = "suspendFallback")
    public Mono<BlockOutcome> unsuspendUser(String casdoorSubject, String reason) {
        log.info("[phpbb] unsuspend-user sub={} reason={} (enabled={})", forLog(casdoorSubject), forLog(reason), enabled);
        return doSuspend(casdoorSubject, reason, false);
    }

    /** Breaker-open / error fallback — degraded, NEVER OK (so the caller stays at 202 pending). */
    @SuppressWarnings("unused")
    private Mono<BlockOutcome> suspendFallback(String casdoorSubject, String reason, Throwable t) {
        log.warn("[phpbb] suspend for {} degraded (breaker/err): {}", forLog(casdoorSubject), t.toString());
        return Mono.just(BlockOutcome.degraded(t.getClass().getSimpleName()));
    }

    /**
     * CWE-117 log-injection guard. Replaces CR/LF and every other ISO control character
     * in a caller-supplied value with {@code '_'} so a crafted ban reason or Casdoor
     * subject cannot inject newlines and forge additional {@code [phpbb] ...} log lines
     * (poisoning the audit trail / any SIEM that parses them). The value is otherwise
     * passed through verbatim — this only affects the LOG render, never the HTTP payload
     * or the {@code forum_action} record. {@code null} renders as the literal {@code "null"}
     * exactly as SLF4J would.
     */
    private static String forLog(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c)) {
                if (sb == null) {
                    sb = new StringBuilder(value.length()).append(value, 0, i);
                }
                sb.append('_');
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb == null ? value : sb.toString();
    }

    /**
     * The single external-call seam. When {@code external.forum.enabled=false} returns
     * {@link BlockOutcome#STUBBED} immediately without any HTTP call (safe default).
     * When enabled:
     * <ul>
     *   <li>{@code suspend=true} — POST {@code /api/v1/hugmesh/admin/users/{sub}/ban}
     *       with a JSON body {@code {"reason": "<reason>"}}; returns {@link BlockOutcome#OK}
     *       on 2xx or {@link BlockOutcome#degraded(String)} on error.</li>
     *   <li>{@code suspend=false} — DELETE {@code /api/v1/hugmesh/admin/users/{sub}/ban};
     *       returns {@link BlockOutcome#OK} on 2xx or {@link BlockOutcome#degraded(String)}
     *       on error.</li>
     * </ul>
     * An idempotent already-suspended/already-lifted response from the extension must be
     * swallowed as OK by the extension; the caller records the outcome regardless.
     */
    private Mono<BlockOutcome> doSuspend(String casdoorSubject, String reason, boolean suspend) {
        if (!enabled) {
            return Mono.just(BlockOutcome.STUBBED);
        }
        if (suspend) {
            // POST the ban with a reason body — extension applies phpBB ban + removes groups
            return http.post()
                    .uri(BASE + "/users/{sub}/ban", casdoorSubject)
                    .bodyValue(Map.of("reason", reason == null ? "" : reason))
                    .retrieve()
                    .toBodilessEntity()
                    .thenReturn(BlockOutcome.OK)
                    .onErrorResume(e -> Mono.just(BlockOutcome.degraded(e.getMessage())));
        } else {
            // DELETE the ban — extension lifts phpBB ban + re-adds groups per current roles
            return http.delete()
                    .uri(BASE + "/users/{sub}/ban", casdoorSubject)
                    .retrieve()
                    .toBodilessEntity()
                    .thenReturn(BlockOutcome.OK)
                    .onErrorResume(e -> Mono.just(BlockOutcome.degraded(e.getMessage())));
        }
    }
}
