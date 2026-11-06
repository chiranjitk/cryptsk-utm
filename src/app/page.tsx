import { AppShell } from "@/components/shell/app-shell";

/**
 * The ONLY user-visible Next.js route (ADR-006 / PROJECT_MEMORY §8).
 * Everything else is hash views inside AppShell.
 */
export default function Home() {
  return <AppShell />;
}
