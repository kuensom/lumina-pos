import { describe, expect, it } from "vitest";

import { issueCredentialGrantSchema } from "../domain/credential-grant-policy";
import { credentialIssueCommandFromFormData } from "./credential-action-input";

function baseForm() {
  const data = new FormData();
  data.set("userId", "7d9ba51f-9c1c-44a6-b13e-40a48b2312c1");
  data.set("purpose", "INITIAL_ENROLMENT");
  data.set("channel", "IN_PERSON");
  return data;
}

describe("credential issuance Server Action input", () => {
  it("rejects a direct submission without explicit identity attestation", () => {
    const command = credentialIssueCommandFromFormData(baseForm());
    expect(issueCredentialGrantSchema.safeParse(command).success).toBe(false);
  });

  it("accepts only the bounded approved attestation value", () => {
    const data = baseForm();
    data.set(
      "verificationAttestation",
      "STAFF_RECORD_AND_MANAGER_ATTESTATION_CONFIRMED",
    );
    expect(
      issueCredentialGrantSchema.safeParse(
        credentialIssueCommandFromFormData(data),
      ).success,
    ).toBe(true);
    data.set("verificationAttestation", "yes-and-extra-client-metadata");
    expect(
      issueCredentialGrantSchema.safeParse(
        credentialIssueCommandFromFormData(data),
      ).success,
    ).toBe(false);
  });
});
