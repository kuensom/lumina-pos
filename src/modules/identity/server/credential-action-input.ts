export function credentialIssueCommandFromFormData(data: FormData) {
  return {
    userId: value(data, "userId"),
    purpose: value(data, "purpose"),
    channel: value(data, "channel"),
    verificationAttestation: value(data, "verificationAttestation"),
  };
}

function value(data: FormData, name: string) {
  const entry = data.get(name);
  return typeof entry === "string" ? entry : "";
}
