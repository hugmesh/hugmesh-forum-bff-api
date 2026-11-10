package net.hugmesh.forumbff.external;

/**
 * The outcome of a phpBB ban/suspend (forum_action BAN congruence) attempt against
 * the phpBB extension. Carried back to the controller so it can be recorded in the
 * {@code forum_action} audit row's {@code outcome} column and surfaced to the
 * admin-ui. MIRRORS the hugmesh-mod-bff-api {@code external.BlockOutcome} shape.
 *
 * <ul>
 *   <li>{@link #STUBBED} — the external admin HTTP call is deliberately NOT made because
 *       the config-gated seam is off by default ({@code external.forum.enabled=false}).
 *       The phpBB extension's shape is confirmed/pinned (see {@link PhpbbAdminClient});
 *       this is a config flip away from going real. The action is still audited locally
 *       in {@code forum_action}.</li>
 *   <li>{@link #OK} — the external call was made and succeeded (only when wired +
 *       enabled).</li>
 *   <li>{@code degraded:<reason>} — the external call was attempted and failed; use
 *       {@link #degraded(String)}.</li>
 * </ul>
 */
public record BlockOutcome(String result) {

    public static final BlockOutcome STUBBED = new BlockOutcome("stubbed");
    public static final BlockOutcome OK = new BlockOutcome("ok");

    /**
     * Width of the {@code forum_action.outcome} column (changelog 002) that every outcome
     * is written to. A longer value makes the audit INSERT fail, and the ban/unban then
     * answers 500 with no audit row instead of 202 pending-reconcile.
     */
    public static final int MAX_RESULT_LENGTH = 64;

    /**
     * A failed external call. The reason should be short (an HTTP status or an exception
     * class name); it is clamped to {@link #MAX_RESULT_LENGTH} so the outcome always fits
     * the audit column.
     */
    public static BlockOutcome degraded(String reason) {
        String result = "degraded:" + reason;
        return new BlockOutcome(result.length() > MAX_RESULT_LENGTH
                ? result.substring(0, MAX_RESULT_LENGTH)
                : result);
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    /**
     * True ONLY when the phpBB ban/suspend actually landed ({@link #OK}). A
     * {@code stubbed} or {@code degraded:<reason>} (breaker-open / error) outcome is
     * NOT ok — the caller must then return {@code 202 pending-reconcile}, never a 200
     * "banned", because the effect was not applied. The reconcile CronJob's
     * de-provisioning pass self-heals.
     */
    public boolean isOk() {
        return "ok".equals(result);
    }
}
