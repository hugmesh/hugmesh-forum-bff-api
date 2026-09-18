package net.hugmesh.forumbff.security;

import org.springframework.web.server.ServerWebExchange;

import net.hugmesh.forumbff.web.StepUpRequiredException;

import java.util.Optional;

/**
 * The step-up FLAVOUR this BFF advertises, and the one-request handoff that tells the
 * access-denied handler a 403 came from the step-up leg rather than from a role leg.
 *
 * <h2>Why a handoff at all</h2>
 * {@code SecurityConfig.stepUp(base, surface)} composes the privileged-path rule as
 * {@code base AND hasAuthority(MFA_SATISFIED)}. When that composition denies, Spring raises
 * an ordinary {@link org.springframework.security.access.AccessDeniedException}, which
 * carries NO record of which conjunct said no — and "you are not an admin" and "you are an
 * admin who has not stepped up" must NOT look the same on the wire: the first must never pop
 * an MFA dialog, and the second is useless without one.
 *
 * <p>Unlike hugmesh-mod-bff-api — whose gate is a {@code @PreAuthorize} conjunct with no
 * exchange in scope, so {@code ModStepUpAccessDeniedHandler} has to RE-DERIVE the answer from
 * a second copy of the gated request shapes — this BFF's gate runs inside
 * {@code authorizeExchange} and therefore already holds the {@link ServerWebExchange}. So the
 * decision is RECORDED at the exact point it is made ({@link #recordDenial}) and READ back by
 * the handler ({@link #deniedSurface}). There is no path inventory to duplicate, and so no
 * inventory to drift: a sixth privileged path group signals correctly the moment it is
 * wrapped in {@code stepUp}, or not at all if it is not.
 *
 * <h2>Fail-CLOSED in the direction that matters</h2>
 * The absence of the attribute means "no signal", i.e. render exactly what Spring would have.
 * A lost attribute therefore degrades to today's behaviour (an unrecognised 403), never to a
 * false step-up prompt and never to a widened grant — this type cannot grant anything, it
 * only ever decorates a refusal that has already been decided.
 *
 * @see StepUpRequiredException
 * @see net.hugmesh.forumbff.config.SecurityConfig
 */
public final class ForumStepUpGate {

    private ForumStepUpGate() {}

    /**
     * The step-up FLAVOUR this BFF advertises, in the platform's {@code X-<flavour>-StepUp}
     * spelling (admin-bff's gates each own one, {@code X-ImageGen-StepUp} being the
     * reference; mod-bff owns {@code X-Mod-StepUp}). It is the VALUE of the
     * {@value StepUpRequiredException#SIGNAL_HEADER} response header on a step-up refusal.
     *
     * <p><b>It is not a request header this service reads.</b> This gate has no token leg —
     * it consumes the {@link Roles#MFA_SATISFIED} marker authority and nothing else — so the
     * client's follow-up is a challenge that stamps the next token followed by a plain RETRY,
     * not a token echoed back here. See {@link StepUpRequiredException} for the whole
     * contract.
     */
    public static final String STEP_UP_HEADER = "X-Forum-StepUp";

    /**
     * The two PRIVILEGED path groups {@code SecurityConfig.commonRoutes} wraps in the step-up
     * composition, each with the verb that reads in its refusal message. The ordinary
     * {@code /bff/forum/**} floor is deliberately absent: reading and posting in the forum is
     * not a privileged action and is not step-up gated.
     */
    public enum Surface {

        /** {@code /bff/forum/admin/**} — the admin-console seam admin-bff calls. */
        ADMIN("forum administration"),

        /** {@code /bff/forum/moderation/**} — the moderation queue and its actions. */
        MODERATION("forum moderation");

        private final String verb;

        Surface(String verb) {
            this.verb = verb;
        }

        /** The operation as it reads in the refusal message. */
        public String verb() {
            return verb;
        }

        /**
         * The refusal to emit when the step-up leg denied on this surface — the ONE place
         * this BFF's flavour is bound to the platform exception, so no caller can hand-roll
         * a 403 a client cannot recognise.
         */
        public StepUpRequiredException denial() {
            return StepUpRequiredException.forRetryHeader(STEP_UP_HEADER, verb);
        }
    }

    /**
     * Exchange-attribute key for the handoff. Fully-qualified so it cannot collide with a
     * framework or application attribute, and deliberately NOT a request/response header:
     * nothing a client sends can set it, and it never reaches the wire.
     */
    private static final String DENIED_ATTRIBUTE = ForumStepUpGate.class.getName() + ".DENIED";

    /**
     * Record that the step-up conjunct — and only it — is what refused this exchange. Called
     * from {@code SecurityConfig.stepUp} at the moment {@code base} has already GRANTED and
     * the {@link Roles#MFA_SATISFIED} leg denies, so the attribute is set if and ONLY if the
     * caller would have been allowed through had they stepped up.
     */
    public static void recordDenial(ServerWebExchange exchange, Surface surface) {
        exchange.getAttributes().put(DENIED_ATTRIBUTE, surface);
    }

    /**
     * The surface whose step-up leg refused this exchange, or empty when the refusal was
     * anything else (a role denial, a method-security denial, or a denial raised while the
     * MFA flag is dark and the wrapper is a pure no-op).
     */
    public static Optional<Surface> deniedSurface(ServerWebExchange exchange) {
        Object recorded = exchange.getAttributes().get(DENIED_ATTRIBUTE);
        return recorded instanceof Surface surface ? Optional.of(surface) : Optional.empty();
    }
}
