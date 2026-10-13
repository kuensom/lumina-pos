export const SESSION_IDLE_MINUTES = 60;
export const SESSION_ABSOLUTE_HOURS = 12;
export const RECENT_AUTHENTICATION_MINUTES = 5;
export const RATE_LIMIT_WINDOW_MINUTES = 15;
export const IDENTIFIER_FAILURE_LIMIT = 5;
export const NETWORK_FAILURE_LIMIT = 30;
export const PROPOSED_SESSION_RETENTION_DAYS = 30;

export function sessionExpiryFrom(now: Date): {
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
} {
  return {
    idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_MINUTES * 60 * 1000),
    absoluteExpiresAt: new Date(
      now.getTime() + SESSION_ABSOLUTE_HOURS * 60 * 60 * 1000,
    ),
  };
}

export function rateLimitWindowStart(now: Date): Date {
  const duration = RATE_LIMIT_WINDOW_MINUTES * 60 * 1000;
  return new Date(Math.floor(now.getTime() / duration) * duration);
}
