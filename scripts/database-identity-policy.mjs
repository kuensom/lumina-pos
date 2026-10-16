export function validateIdentitySet({
  primary,
  runtime,
  shadow,
  rollback,
  context = "local",
  operation = "inspect",
}) {
  const names = approvedNames(context);
  assertApproved(primary, names.primary, "migration");
  assertApproved(runtime, names.primary, "runtime");
  assertApproved(shadow, names.shadow, "shadow");
  if (sameDatabase(primary, shadow) || sameDatabase(runtime, shadow)) {
    throw new Error(
      "Shadow database must be physically distinct from the primary database.",
    );
  }
  if (!sameDatabase(primary, runtime)) {
    throw new Error(
      "Runtime and migration URLs must target the same development database.",
    );
  }
  if (primary.user === runtime.user) {
    throw new Error(
      "Migration-owner and runtime database roles must be distinct.",
    );
  }
  if (operation === "reset") {
    throw new Error(
      "Repository reset commands are prohibited for primary and shadow databases.",
    );
  }
  if (operation === "rollback") {
    if (!rollback) throw new Error("Rollback database identity is required.");
    assertApproved(rollback, names.rollback, "rollback");
    if (
      sameDatabase(rollback, primary) ||
      sameDatabase(rollback, runtime) ||
      sameDatabase(rollback, shadow)
    )
      throw new Error(
        "Rollback database must be physically distinct from primary and shadow databases.",
      );
  }
}

function approvedNames(context) {
  if (context === "local")
    return {
      primary: "lumina_pos_dev",
      shadow: "lumina_pos_shadow",
      rollback: "lumina_pos_b4_rollback_test",
    };
  if (context === "ci")
    return {
      primary: "lumina_ci",
      shadow: "lumina_ci_shadow",
      rollback: "lumina_ci_rollback_test",
    };
  throw new Error(`Unknown database safety context: ${context}.`);
}

function assertApproved(value, expectedDatabase, label) {
  if (value.database !== expectedDatabase)
    throw new Error(
      `${label} database must be ${expectedDatabase}; received ${value.database}.`,
    );
  if (/prod|production|stage|staging/i.test(value.database))
    throw new Error(
      `${label} database has a forbidden production/staging identity.`,
    );
  if (!["127.0.0.1", "::1", "localhost"].includes(value.connectionHost))
    throw new Error(
      `${label} database is not on an approved local PostgreSQL instance.`,
    );
}

function sameDatabase(left, right) {
  return (
    left.database === right.database &&
    left.host === right.host &&
    left.port === right.port
  );
}
