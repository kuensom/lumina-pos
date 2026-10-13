/**
 * Contract only: B1 intentionally provides no executable username-change path.
 *
 * The future implementation must authenticate the actor as a Super
 * Administrator and run one serializable transaction that locks the target,
 * normalizes and uniquely validates the username, updates both username
 * columns, increments authzVersion, revokes every target session, and appends
 * the immutable identity.username_changed audit event before commit. Ordinary
 * staff-update inputs must not expose username fields.
 *
 * Once privileged MFA exists, this action must also require recent MFA-backed
 * authentication. A caller-provided flag must never substitute for a server-
 * verified protected-role and recent-authentication check.
 */
export interface ChangeUsernameApplicationService {
  execute(command: ChangeUsernameCommand): Promise<void>;
}

export type ChangeUsernameCommand = Readonly<{
  actorUserId: string;
  targetUserId: string;
  newUsername: string;
  correlationId: string;
  occurredAt: Date;
}>;

export const USERNAME_CHANGED_AUDIT_EVENT = "identity.username_changed";
