export type UserSecurityState = {
  id: string;
  status: "PENDING_PASSWORD" | "ACTIVE" | "INACTIVE" | "LOCKED";
  authzVersion: number;
};

export type EffectivePermission = {
  code: string;
  requiresSuperAdmin: boolean;
};

export interface UserRepository {
  findSecurityStateById(id: string): Promise<UserSecurityState | null>;
  findIdByNormalizedIdentifier(identifier: string): Promise<string | null>;
}

export interface AuthorizationRepository {
  listEffectivePermissions(
    userId: string,
  ): Promise<readonly EffectivePermission[]>;
  hasActiveProtectedRole(userId: string): Promise<boolean>;
}

export interface SessionRepository {
  findActiveByTokenHash(
    tokenHash: string,
    now: Date,
  ): Promise<{
    id: string;
    userId: string;
    authzVersion: number;
    idleExpiresAt: Date;
    absoluteExpiresAt: Date;
  } | null>;
  revokeForUser(userId: string, reason: string, now: Date): Promise<number>;
}

export interface PasswordResetGrantRepository {
  consumeOnce(input: {
    tokenHash: string;
    userId: string;
    now: Date;
  }): Promise<{ id: string } | null>;
}

export interface AuditRepository {
  append(event: {
    actorUserId: string | null;
    eventType: string;
    targetType: string | null;
    targetId: string | null;
    outcome: "SUCCESS" | "DENIED" | "FAILURE";
    correlationId: string;
    metadata: Readonly<Record<string, unknown>> | null;
  }): Promise<void>;
}

/**
 * Contract for future role and permission mutations. Implementations must run
 * each operation in one serializable transaction: lock the affected role,
 * apply protected-capability guards, mutate memberships/grants, increment
 * authzVersion for every affected active user, revoke protected-change
 * sessions, and append the audit event before commit.
 */
export interface RoleAdministrationRepository {
  replaceRolePermissions(input: {
    actorUserId: string;
    roleId: string;
    permissionIds: readonly string[];
    correlationId: string;
  }): Promise<void>;
  assignRole(input: {
    actorUserId: string;
    userId: string;
    roleId: string;
    correlationId: string;
  }): Promise<void>;
  removeRole(input: {
    actorUserId: string;
    userId: string;
    roleId: string;
    correlationId: string;
  }): Promise<void>;
}
