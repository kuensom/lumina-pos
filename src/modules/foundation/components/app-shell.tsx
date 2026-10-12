import Link from "next/link";
import type { ReactNode } from "react";

const navigation = [
  { href: "/", label: "Dashboard" },
  { href: "/login", label: "Login placeholder" },
];

export function AppShell({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-emerald-950/20 bg-forest text-white">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-4 px-5 py-4 sm:px-8">
          <Link href="/" className="text-xl font-bold no-underline">
            Lumina POS
          </Link>
          <nav aria-label="Primary navigation">
            <ul className="flex flex-wrap gap-5 text-sm font-medium">
              {navigation.map((item) => (
                <li key={item.href}>
                  <Link href={item.href} className="hover:underline">
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>
      <div className="flex flex-1">{children}</div>
      <footer className="border-t border-slate-300 px-5 py-4 text-center text-sm text-slate-600">
        Foundation only — no live POS operations
      </footer>
    </div>
  );
}
