import { getStaffDetail } from "@/modules/identity/application/administration-service";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import { issueCredentialAction } from "@/modules/identity/server/credential-actions";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";
import { CredentialForm } from "@/modules/identity/ui/credential-form";

export default async function StaffCredentialsPage({
  params,
}: {
  params: Promise<{ userId: string }>;
}) {
  const { userId } = await params;
  const claims = await administrationPageClaims();
  let detail;
  try {
    detail = await getStaffDetail({ prisma, claims, userId });
  } catch (error) {
    handleAdministrationPageError(error);
  }
  const initial = detail.user.status === "PENDING_PASSWORD";
  return (
    <main className="mx-auto max-w-2xl px-5 py-10">
      <h1 className="text-3xl font-bold">
        Credentials for {detail.user.displayName}
      </h1>
      <p className="my-4">
        Identity must be checked against staff records and confirmed by an
        authorised manager. Inactive accounts are not eligible.
      </p>
      <CredentialForm
        action={issueCredentialAction}
        submitLabel="Issue one-time credential"
      >
        <input type="hidden" name="userId" value={userId} />
        <input
          type="hidden"
          name="purpose"
          value={initial ? "INITIAL_ENROLMENT" : "ADMINISTRATOR_RESET"}
        />
        <label className="block">
          <span>Delivery channel</span>
          <select name="channel" className="mt-1 w-full rounded border p-2">
            <option value="IN_PERSON">Secure in-person handover</option>
            <option value="EMAIL" disabled={!detail.user.email}>
              Verified email / enrollment invitation
            </option>
          </select>
        </label>
        <label className="flex gap-2">
          <input
            type="checkbox"
            name="verificationAttestation"
            value="STAFF_RECORD_AND_MANAGER_ATTESTATION_CONFIRMED"
            required
          />
          I compared the person against staff records and confirm the manager
          attestation.
        </label>
      </CredentialForm>
    </main>
  );
}
