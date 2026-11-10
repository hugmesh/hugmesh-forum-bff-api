package net.hugmesh.forumbff.forum;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.forumbff.phpbb.PhpbbApiClient;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code POST /bff/forum/system/private-messages}: the forum-bff hop of the contract
 * admin-bff's {@code ForumSystemPmClient} documents. It forwards the {@code @system}
 * caller's request to the forum-api extension's
 * {@code POST /api/v1/hugmesh/system/private-messages} with the caller's own bearer, the
 * same {@code Idempotency-Key} and the same three body fields.
 *
 * <h3>Who may call it</h3>
 * {@code ROLE_SYSTEM} only: the path rule in {@code SecurityConfig} and the
 * {@code @PreAuthorize} below both say so, and neither applies the
 * SUPERADMIN&gt;ADMIN hierarchy to it (SYSTEM is not in that hierarchy at all). The
 * extension checks the same role again on the forwarded token.
 *
 * <h3>Answers</h3>
 * <ul>
 *   <li>The extension's 2xx whose body is a JSON object with a numeric {@code id}: passed
 *       through (status and body bytes), plus {@code Idempotent-Replayed: true} when the
 *       extension replayed the key.</li>
 *   <li>{@code 404 {"code":"unknown_recipient"}} from the extension: the same 404 and that
 *       exact body (admin-bff turns it into a terminal SKIP).</li>
 *   <li>{@code 409 idempotency_in_progress} / {@code 422 idempotency_key_reused}: passed
 *       through as {@code {"code":...}}.</li>
 *   <li>Anything else from the extension (another 404, i.e. the route is missing; 401/403;
 *       5xx; a 2xx that is not the documented body) or a transport error/timeout:
 *       {@code 502 {"code":"forum_upstream_error"}}. Never a 404, so admin-bff retries.</li>
 *   <li>{@code phpbb.enabled=false}: {@code 503 {"code":"forum_unavailable"}}, no call.</li>
 * </ul>
 */
@Tag(name = "ForumSystem", description = "@system machine seam (admin-bff notifications): "
        + "send a phpBB private message from the @system account. ROLE_SYSTEM only.")
@RestController
@RequestMapping("/bff/forum/system")
@Validated
public class SystemPrivateMessageController {

    private static final Logger log = LoggerFactory.getLogger(SystemPrivateMessageController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** The same key shape the extension accepts: 1-255 visible ASCII characters. */
    private static final Pattern KEY = Pattern.compile("[\\x21-\\x7E]{1,255}");

    static final String UNKNOWN_RECIPIENT = "unknown_recipient";
    private static final Set<String> PASS_THROUGH_CODES = Set.of(
            "409:idempotency_in_progress", "422:idempotency_key_reused");

    private final PhpbbApiClient phpbb;

    public SystemPrivateMessageController(PhpbbApiClient phpbb) {
        this.phpbb = phpbb;
    }

    @Operation(operationId = "sendSystemPrivateMessage",
            summary = "Send a phpBB private message from the @system account to the user mapped from a Casdoor subject (idempotent).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Sent, or the same Idempotency-Key and body replayed: {\"id\": <phpBB msg_id>}"),
            @ApiResponse(responseCode = "400", description = "Missing/invalid Idempotency-Key or body"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated"),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_SYSTEM (admin and superadmin included)"),
            @ApiResponse(responseCode = "404", description = "{\"code\":\"unknown_recipient\"}: the subject maps to no phpBB user"),
            @ApiResponse(responseCode = "409", description = "{\"code\":\"idempotency_in_progress\"}"),
            @ApiResponse(responseCode = "422", description = "{\"code\":\"idempotency_key_reused\"}: same key, different body"),
            @ApiResponse(responseCode = "502", description = "{\"code\":\"forum_upstream_error\"}: the extension failed or is missing the route"),
            @ApiResponse(responseCode = "503", description = "{\"code\":\"forum_unavailable\"}: phpbb.enabled=false")
    })
    @PreAuthorize("hasRole('SYSTEM')")
    @PostMapping(value = "/private-messages", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<String>> send(
            @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody ForumDto.SystemPrivateMessage body,
            Authentication auth) {
        String key = idempotencyKey == null ? "" : idempotencyKey.trim();
        if (!KEY.matcher(key).matches()) {
            return Mono.just(code(HttpStatus.BAD_REQUEST, "invalid_idempotency_key"));
        }
        String bearer = bearerOf(auth);
        if (bearer == null) {
            // Unreachable behind the resource server (every authenticated principal here is
            // a JWT); refuse rather than forward without the caller's identity.
            return Mono.just(code(HttpStatus.UNAUTHORIZED, "no_bearer"));
        }
        return phpbb.sendSystemPrivateMessage(bearer, key, body)
                .map(SystemPrivateMessageController::map)
                .onErrorResume(e -> {
                    log.warn("[forum-system-pm] extension call failed: {}", e.toString());
                    return Mono.just(code(HttpStatus.BAD_GATEWAY, "forum_upstream_error"));
                })
                .switchIfEmpty(Mono.fromSupplier(() -> code(HttpStatus.SERVICE_UNAVAILABLE, "forum_unavailable")));
    }

    /** Map the extension's answer onto this route's contract (see the class javadoc). */
    static ResponseEntity<String> map(PhpbbApiClient.SystemPmReply reply) {
        int status = reply.status();
        JsonNode json = parse(reply.body());
        if (status >= 200 && status < 300) {
            if (json != null && json.isObject() && json.path("id").isIntegralNumber()) {
                ResponseEntity.BodyBuilder ok = ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON);
                if (reply.replayed()) {
                    ok.header("Idempotent-Replayed", "true");
                }
                return ok.body(reply.body());
            }
            log.warn("[forum-system-pm] extension answered {} without the documented {{\"id\":n}} body", status);
            return code(HttpStatus.BAD_GATEWAY, "forum_upstream_error");
        }
        String upstreamCode = json != null && json.isObject() ? json.path("code").asText("") : "";
        if (status == 404 && UNKNOWN_RECIPIENT.equals(upstreamCode)) {
            return code(HttpStatus.NOT_FOUND, UNKNOWN_RECIPIENT);
        }
        if (PASS_THROUGH_CODES.contains(status + ":" + upstreamCode)) {
            return code(HttpStatus.valueOf(status), upstreamCode);
        }
        log.warn("[forum-system-pm] extension answered {} (mapped to 502)", status);
        return code(HttpStatus.BAD_GATEWAY, "forum_upstream_error");
    }

    private static String bearerOf(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwt) {
            return jwt.getToken().getTokenValue();
        }
        return null;
    }

    private static ResponseEntity<String> code(HttpStatus status, String code) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body(MAPPER.createObjectNode().put("code", code).toString());
    }

    private static JsonNode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            return null;
        }
    }
}
