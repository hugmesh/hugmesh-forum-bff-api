package net.hugmesh.forumbff.forum;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of the NEW {@code forum_action} audit table (Liquibase {@code 002}). This is
 * forum-bff's OWN audit trail — it deliberately does NOT reuse / widen the
 * hugmesh-mod-bff-api {@code mod_action} table or its {@code ck_mod_action_platform}
 * CHECK (the design is explicit: mirror the mod-bff shape with our OWN table; never
 * touch mod-bff).
 *
 * <p>Every forum admin/congruence action is audited regardless of the external outcome
 * (ok / stubbed / degraded), so a stubbed phpBB ban is still fully auditable — exactly
 * the mod-bff {@code mod_action} contract.
 *
 * <p>The {@code domain} (Liquibase {@code 003}) is the brand/tenant the action belongs
 * to, stamped SERVER-SIDE from the actor's validated-issuer brand (NEVER a request
 * field). A forum admin/mod of brand X reads only brand X's trail; SUPERADMIN reads
 * every brand's. A single-tenant cluster carries the platform {@code default} domain.
 *
 * @param actorSubject the acting principal (Casdoor JWT subject/name)
 * @param action       the action verb (e.g. {@code admin.forum.user.ban}, {@code admin.forum.style.install})
 * @param target       the target (Casdoor sub / category / style name)
 * @param outcome      the external-call outcome ({@code ok} / {@code stubbed} / {@code degraded:...})
 * @param detail       free-text reason / detail (nullable)
 * @param domain       the brand/tenant the action belongs to (server-derived; {@code default} single-tenant)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Table("forum_action")
public record ForumAction(
        @Id @Column("id") String id,
        @Column("actor_subject") String actorSubject,
        @Column("action") String action,
        @Column("target") String target,
        @Column("outcome") String outcome,
        @Column("detail") String detail,
        @Column("created_at") Instant createdAt,
        @Column("domain") String domain) {
}
