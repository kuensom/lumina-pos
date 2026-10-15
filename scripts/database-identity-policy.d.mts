export interface DatabaseIdentity {
  database: string;
  user: string;
  host: string;
  port: number;
  connectionHost: string;
}

export interface DatabaseIdentitySet {
  primary: DatabaseIdentity;
  runtime: DatabaseIdentity;
  shadow: DatabaseIdentity;
  rollback?: DatabaseIdentity;
  context?: "local" | "ci";
  operation?: "inspect" | "migrate" | "drift" | "reset" | "rollback";
}

export function validateIdentitySet(identities: DatabaseIdentitySet): void;
