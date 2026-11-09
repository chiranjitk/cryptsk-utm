"use client";

/**
 * BrandLogo — the Cryptsk brand mark (gradient shield + keyhole).
 * Single source of truth for every logo surface: sidebar, login, setup
 * wizard and the console boot screen. `src/app/icon.svg` mirrors it for
 * the favicon (Next.js file convention) and `public/logo.svg` for
 * bookmark/og use. Sized via className (h-8 w-8, h-12 w-12, …).
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
        <linearGradient id="ck-brand-gradient" x1="7" y1="3" x2="57" y2="61" gradientUnits="userSpaceOnUse">
          <stop stopColor="#3b82f6" />
          <stop offset="1" stopColor="#7c3aed" />
        </linearGradient>
      </defs>
      {/* shield */}
      <path
        d="M32 3 L57 12.5 V29 C57 46.5 46.8 57.6 32 61.5 C17.2 57.6 7 46.5 7 29 V12.5 Z"
        fill="url(#ck-brand-gradient)"
      />
      {/* inner outline */}
      <path
        d="M32 9.5 L51 16.8 V29.2 C51 42.4 43.2 51.4 32 55.2 C20.8 51.4 13 42.4 13 29.2 V16.8 Z"
        stroke="#ffffff"
        strokeOpacity="0.35"
        strokeWidth="2"
        fill="none"
      />
      {/* keyhole */}
      <circle cx="32" cy="26.5" r="7.2" fill="#ffffff" />
      <path d="M32 30.5 L27.4 44.6 Q32 47.4 36.6 44.6 Z" fill="#ffffff" />
    </svg>
  );
}
