import { NextResponse } from "next/server";

import { healthPayload } from "@/modules/foundation/health";

export function GET() {
  return NextResponse.json(healthPayload());
}
