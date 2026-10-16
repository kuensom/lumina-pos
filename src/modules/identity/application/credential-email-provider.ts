export type CredentialEmailMessage = {
  idempotencyKey: string;
  recipient: string;
  setupFragmentUrl: string;
  expiresAt: Date;
  purpose: "INITIAL_ENROLMENT" | "ADMINISTRATOR_RESET";
};

export type CredentialEmailResult =
  | { accepted: true; messageId: string }
  | {
      accepted: false;
      failureCode: "CONFIGURATION" | "REJECTED" | "TEMPORARY";
    };

export interface CredentialEmailProvider {
  send(message: CredentialEmailMessage): Promise<CredentialEmailResult>;
}

export class DisabledCredentialEmailProvider
  implements CredentialEmailProvider
{
  async send(): Promise<CredentialEmailResult> {
    return { accepted: false, failureCode: "CONFIGURATION" };
  }
}

export class FakeCredentialEmailProvider implements CredentialEmailProvider {
  readonly messages: CredentialEmailMessage[] = [];
  async send(message: CredentialEmailMessage): Promise<CredentialEmailResult> {
    this.messages.push(message);
    return { accepted: true, messageId: `fake-${this.messages.length}` };
  }
}
