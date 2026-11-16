"use client";

/**
 * DesignGalleryLink — floating pill that opens the 10-template redesign gallery
 * (public/design-templates.html). Temporary affordance while the user picks the
 * new app-wide look; removed once the redesign lands.
 */

import { Palette } from "lucide-react";

export function DesignGalleryLink() {
  return (
    <a
      href="/design-templates.html"
      target="_blank"
      rel="noreferrer"
      title="Pick a new look for the whole app — 10 design templates"
      className="fixed bottom-4 right-4 z-50 flex min-h-11 items-center gap-2 rounded-full border border-border bg-background/90 px-4 py-2 text-xs font-semibold shadow-lg backdrop-blur transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
    >
      <Palette className="h-4 w-4 shrink-0" aria-hidden="true" />
      <span>
        New look — <span className="font-bold">pick 1 of 10 templates</span>
      </span>
    </a>
  );
}
