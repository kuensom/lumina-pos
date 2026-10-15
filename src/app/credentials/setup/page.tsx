import { redeemCredentialAction } from "@/modules/identity/server/credential-actions";
import { CredentialForm } from "@/modules/identity/ui/credential-form";
import { CredentialInput } from "@/modules/identity/ui/credential-input";

export const metadata = {
  title: "Set password",
  referrer: "same-origin" as const,
};
export const dynamic = "force-dynamic";

export default function CredentialSetupPage() {
  return (
    <main className="mx-auto max-w-lg px-5 py-12">
      <h1 className="text-3xl font-bold">Set your password</h1>
      <p className="my-4">
        Enter the one-time voucher or use the secure invitation delivered to
        you. Credentials expire after 15 minutes.
      </p>
      <CredentialForm
        action={redeemCredentialAction}
        submitLabel="Save password"
      >
        <CredentialInput />
        <label className="block">
          <span>New password</span>
          <input
            name="password"
            type="password"
            required
            minLength={12}
            maxLength={128}
            className="mt-1 w-full rounded border p-2"
          />
        </label>
        <label className="block">
          <span>Confirm password</span>
          <input
            name="passwordConfirmation"
            type="password"
            required
            minLength={12}
            maxLength={128}
            className="mt-1 w-full rounded border p-2"
          />
        </label>
      </CredentialForm>
    </main>
  );
}
