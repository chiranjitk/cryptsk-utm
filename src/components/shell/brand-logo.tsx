"use client";

/**
 * BrandLogo — the Cryptsk brand mark (v3: rounded hexagon badge + ring
 * keyhole, defense-in-depth inner outline). Single source of truth for
 * every logo surface: sidebar, login, setup wizard and the console boot
 * screen. `src/app/icon.svg` mirrors it for the favicon (Next.js file
 * convention) and `public/logo.svg` for bookmark/og use. Sized via
 * className (h-8 w-8, h-12 w-12, …).
 *
 * Palette (LOCKED, owner-directed white/red/dark-red brand):
 *   #ef4444 → #c81e1e → #7f1d1d
 */

export function BrandLogo({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Cryptsk logo"
      className={className}
    >
      <defs>
        <linearGradient id="ck-brand-gradient" x1="12" y1="4" x2="52" y2="60" gradientUnits="userSpaceOnUse">
          <stop stopColor="#ef4444" />
          <stop offset="0.55" stopColor="#c81e1e" />
          <stop offset="1" stopColor="#7f1d1d" />
        </linearGradient>
      </defs>
      {/* hexagon badge — stroke shares the gradient to soften the corners */}
      <path
        d="M32 5 L55 18 V46 L32 59 L9 46 V18 Z"
        fill="url(#ck-brand-gradient)"
        stroke="url(#ck-brand-gradient)"
        strokeWidth="6"
        strokeLinejoin="round"
      />
      {/* inner defense-in-depth outline */}
      <path
        d="M32 14 L47.5 22.9 V40.9 L32 49.8 L16.5 40.9 V22.9 Z"
        fill="none"
        stroke="#ffffff"
        strokeOpacity="0.35"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      {/* ring keyhole */}
      <circle cx="32" cy="27.5" r="6" fill="none" stroke="#ffffff" strokeWidth="3.4" />
      <path d="M32 31.5 L27.6 44 Q32 46.4 36.4 44 Z" fill="#ffffff" />
    </svg>
  );
}
