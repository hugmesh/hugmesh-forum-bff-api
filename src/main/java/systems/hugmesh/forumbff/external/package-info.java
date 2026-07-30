/**
 * Outbound seams for optional external integrations: the phpBB admin
 * ban/suspend client and the shared {@code BlockOutcome} result type.
 * All calls are circuit-breaker-wrapped and flag-gated by
 * {@code external.forum.enabled}; when the flag is true, the client makes the
 * real HTTP call against the confirmed phpBB extension admin API shape.
 */
package systems.hugmesh.forumbff.external;
