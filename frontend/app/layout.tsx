import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentSeal — Proof of Capability",
  description:
    "Verify autonomous-agent capabilities with immutable policy bindings and GenLayer consensus.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
