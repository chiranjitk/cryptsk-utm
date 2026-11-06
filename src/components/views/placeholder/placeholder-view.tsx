"use client";

/**
 * Placeholder view — every view that its module (M02-M11) has not shipped yet.
 * Shows exactly which module + doc to read, per the docs-first protocol.
 */

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Hammer, ArrowRight } from "lucide-react";
import type { ViewDef } from "@/components/shell/nav-config";

export function PlaceholderView({ view }: { view: ViewDef }) {
  return (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center gap-3 p-10 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400">
          <Hammer className="h-6 w-6" />
        </div>
        <div>
          <p className="font-semibold">{view.title}</p>
          <p className="mt-1 text-sm text-zinc-500">
            This view ships with module <Badge variant="outline" className="mx-1 border-amber-500/40 text-amber-600 dark:text-amber-400">{view.placeholder}</Badge>
            (see <code className="rounded bg-zinc-100 px-1 text-xs dark:bg-zinc-800">docs/06-MODULES/{view.placeholder}-*.md</code>).
          </p>
        </div>
        <p className="flex items-center gap-1 text-xs text-zinc-400">
          M0 foundation is live — module build order per ADR-014 <ArrowRight className="inline h-3 w-3" />
        </p>
      </CardContent>
    </Card>
  );
}
