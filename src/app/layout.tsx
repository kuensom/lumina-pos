import type { Metadata } from "next";
import type { ReactNode } from "react";

import { AppShell } from "@/modules/foundation/components/app-shell";

import "./globals.css";

export const metadata: Metadata = {
  title: "Lumina POS",
  description: "Lumina POS application foundation",
};

export default function RootLayout({
  children,
}: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
