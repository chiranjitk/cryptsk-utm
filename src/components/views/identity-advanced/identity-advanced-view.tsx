"use client";

/**
 * #/identity/federation + #/identity/nac — Advanced Identity & NAC (M23,
 * spec 2.9 + 2.10) section router. ONE component is registered under two nav
 * paths: it reads window.location.hash (+ hashchange listener) and renders
 * the matching dedicated view — FederationView (SSO IdPs, RADIUS CoA
 * profiles, activity timeline) from federation-view.tsx or NacView (stats,
 * NAC profiles, device inventory, BYOD onboarding) from nac-view.tsx.
 * Theme (ADR-019): red-700 enterprise accents, zinc neutrals, rose-600
 * danger, amber-500 warning — emerald/teal/indigo/violet/cyan are forbidden.
 */

import { useEffect, useState } from "react";
import { FederationView } from "./federation-view";
import { NacView } from "./nac-view";

function useHashPath(): string {
  const [path, setPath] = useState("");
  useEffect(() => {
    const read = () => {
      const hash = window.location.hash || "#/identity/federation";
      const clean = (hash.startsWith("#") ? hash.slice(1) : hash).split("?")[0] || "/identity/federation";
      setPath(clean);
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  return path;
}

export function IdentityAdvancedView() {
  const path = useHashPath();
  if (path === "/identity/nac") return <NacView />;
  return <FederationView />;
}
