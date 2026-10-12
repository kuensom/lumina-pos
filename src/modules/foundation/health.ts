export type HealthPayload = {
  status: "ok";
  service: "lumina-pos";
};

export function healthPayload(): HealthPayload {
  return { status: "ok", service: "lumina-pos" };
}
