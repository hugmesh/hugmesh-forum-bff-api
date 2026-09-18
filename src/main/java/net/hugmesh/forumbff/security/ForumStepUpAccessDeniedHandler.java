package net.hugmesh.forumbff.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import net.hugmesh.forumbff.web.StepUpRequiredException;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Makes a STEP-UP refusal recognisable on the wire, and changes nothing else.
 *
 * <h2>The problem</h2>
 * {@code SecurityConfig.stepUp} composes the privileged-path rule as {@code base AND
 * hasAuthority(MFA_SATISFIED)}. A deny from either conjunct arrives at the chain's
 * access-denied handler as the same bare {@link AccessDeniedException} — 403, no body, no
 * header — so "you are not an admin" and "you are an admin who has not stepped up" are
 * byte-identical on the wire. hugmesh-forum-ui ships the client half of the step-up flow and
 * it is INERT against that denial, because neither of its detection legs can match it. See
 * hugmesh-forum-bff-api#15.
 *
 * <h2>What this handler does</h2>
 * It is installed as the chain's {@code accessDeniedHandler} and, for the narrow case below,
 * renders the refusal exactly as {@link net.hugmesh.forumbff.web.ApiExceptionHandler} renders
 * a {@link StepUpRequiredException} — status 403 (unchanged), the shared
 * {@code {"error": "<message>"}} body, and the {@value StepUpRequiredException#SIGNAL_HEADER}
 * response header naming the flavour. EVERY other denial is delegated, untouched, to
 * {@link #DEFAULT} — the very handler Spring Security installs on THIS chain when nothing
 * overrides it — so no other refusal's wire shape moves.
 *
 * <h2>The narrow case</h2>
 * Exactly one condition: {@link ForumStepUpGate#deniedSurface} is present, i.e.
 * {@code SecurityConfig.stepUp} recorded — at the moment it decided — that {@code base} had
 * already GRANTED and the {@code MFA_SATISFIED} leg is what denied. Nothing is re-derived
 * here, because the decision point had the exchange in hand.
 *
 * <p>That single condition subsumes the four hugmesh-mod-bff-api's handler has to re-check
 * ({@code ModStepUpAccessDeniedHandler}, whose {@code @PreAuthorize} gate leaves it no
 * exchange to read):
 * <ul>
 *   <li><b>armed?</b> — while {@code app.mfa.enabled} is dark, {@code stepUp} returns
 *       {@code base} unwrapped, so nothing can record the attribute and this handler is a
 *       pure pass-through;</li>
 *   <li><b>a gated request shape?</b> — only the two wrapped path groups run the
 *       composition at all;</li>
 *   <li><b>did the caller pass the ROLE half?</b> — the attribute is written only AFTER
 *       {@code base} granted, so a plain user's role 403 on {@code /bff/forum/admin/**}
 *       never carries the signal and forum-ui never offers them a challenge that could not
 *       possibly let them through;</li>
 *   <li><b>is step-up the leg that failed?</b> — that IS the recorded fact.</li>
 * </ul>
 *
 * <p>A method-security denial ({@code ModerationController}'s AND-of-MOD+FORUM
 * {@code @PreAuthorize}) propagates to this same handler, and carries no attribute — the path
 * gate granted — so it is passed through unsignalled, which is what issue #15 requires. An
 * unauthenticated caller never reaches here at all:
 * {@link org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter}
 * routes an anonymous/absent principal to the authentication entry point (401) instead.
 *
 * <h2>Why the delegate is the BEARER handler, not {@link HttpStatusServerAccessDeniedHandler}</h2>
 * Installing an explicit {@code accessDeniedHandler} makes {@code ServerHttpSecurity} discard
 * its {@code defaultAccessDeniedHandlers} wholesale, so the delegate has to be chosen to
 * match what those defaults resolve to — and for a chain that configures
 * {@code oauth2ResourceServer} (both of this service's chains do) that is
 * {@code BearerTokenServerAccessDeniedHandler}, NOT the bare status handler. MEASURED in this
 * repo on 2026-09-18 (the same trap a skeptic round caught in mod-bff PR #18), against a
 * chain built exactly like {@code SecurityConfig.filterChain} minus the
 * {@code exceptionHandling} call, refusing on {@code GET /bff/forum/admin/stats}:
 *
 * <pre>
 *   no OAuth2 principal on the exchange
 *     Spring's own:         403, WWW-Authenticate: Bearer, empty body
 *     bare status handler:  403, NO WWW-Authenticate, Content-Type: text/plain,
 *                                body "Access Denied"
 *
 *   an authenticated JwtAuthenticationToken — what EVERY production 403 here has, since a
 *   denial only reaches an access-denied handler once the caller is authenticated
 *     Spring's own:         403, empty body, and the full RFC 6750 challenge
 *                                WWW-Authenticate: Bearer error="insufficient_scope",
 *                                  error_description="The request requires higher privileges
 *                                  than provided by the access token.",
 *                                  error_uri="https://tools.ietf.org/html/rfc6750#section-3.1"
 *     bare status handler:  403, NO WWW-Authenticate, Content-Type: text/plain,
 *                                body "Access Denied"
 * </pre>
 *
 * i.e. delegating to the bare status handler would have silently changed EVERY non-step-up
 * 403 this service emits — destroying the whole challenge and inventing a body — which is
 * precisely what this handler promises not to do. The second row is the one that matters and
 * the one a careless measurement misses: an unauthenticated mock exchange makes the two
 * handlers look far closer than they are. {@code StepUpAccessDeniedWiringTest} pins the
 * equivalence on BOTH shapes, comparing status, every header and the body, and
 * {@code MfaStepUpPathGateSliceTest} asserts the challenge string end to end through the real
 * chain — so a future Spring that resolves its defaults differently goes red here rather than
 * changing the wire under a green suite.
 *
 * <p>The STEP-UP response is the one deliberate exception: it is a new shape by design (it
 * gains the signal header and a JSON body) and does not carry {@code WWW-Authenticate},
 * because re-presenting the same bearer credential is exactly what will NOT satisfy it.
 *
 * @see ForumStepUpGate
 * @see StepUpRequiredException
 */
public class ForumStepUpAccessDeniedHandler implements ServerAccessDeniedHandler {

    /**
     * Exactly what {@code ServerHttpSecurity} installs on a chain that configures
     * {@code oauth2ResourceServer} and nothing else — see the class javadoc for the
     * measurement. Stateless and thread-safe, so one instance serves every chain.
     */
    private static final ServerAccessDeniedHandler DEFAULT =
            new BearerTokenServerAccessDeniedHandler();

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        return ForumStepUpGate.deniedSurface(exchange)
                .map(surface -> writeStepUpRefusal(exchange, surface))
                .orElseGet(() -> DEFAULT.handle(exchange, denied));
    }

    /**
     * Render the refusal. The status, body shape and header value are all taken FROM the
     * exception, so this handler and {@link net.hugmesh.forumbff.web.ApiExceptionHandler}
     * cannot disagree — {@link ForumStepUpGate.Surface#denial()} is the one place either of
     * them mints.
     */
    private static Mono<Void> writeStepUpRefusal(ServerWebExchange exchange,
                                                 ForumStepUpGate.Surface surface) {
        StepUpRequiredException refusal = surface.denial();
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(refusal.status());
        response.getHeaders().set(StepUpRequiredException.SIGNAL_HEADER, refusal.retryHeader());
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buffer = response.bufferFactory().wrap(errorBody(refusal.getMessage()));
        return response.writeWith(Mono.just(buffer));
    }

    /** {@code {"error": "<message>"}} — the shape {@code ApiExceptionHandler} emits, built
     *  through Jackson so no message can produce malformed JSON. */
    private static byte[] errorBody(String message) {
        try {
            return JSON.writeValueAsBytes(Map.of("error", message));
        } catch (JsonProcessingException e) {
            // Unreachable for a Map<String,String>; fall back rather than failing the
            // response, since the caller is already being refused. Composed from
            // LEGACY_PHRASE, never hand-spelled: that constant is the ONE place main sources
            // emit the phrase an old phrase-sniffing client greps for, and
            // StepUpSignalContractTest.theEmittedLegacyPhraseLivesInExactlyOneMainSource
            // fails the build on a second copy — as it did on this line's first draft.
            return ("{\"error\":\"" + StepUpRequiredException.LEGACY_PHRASE
                    + " re-authentication\"}").getBytes(StandardCharsets.UTF_8);
        }
    }
}
