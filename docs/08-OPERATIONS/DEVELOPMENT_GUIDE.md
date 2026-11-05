# Development Guide — Sandbox Environment and Workflow

> TL;DR: Bun runtime, Next.js dev server on port 3000 (background, logs to
> `/home/z/my-project/dev.log`), SQLite via Prisma, socket.io mini-service on 3003 behind
> the gateway (`?XTransformPort=3003`). Verification = lint + dev.log + browser. Never
> `bun run build`. Schema source of truth is `docs/03-DATABASE/SCHEMA.md`. Every task ends
> with docs updated + session log appended.
>
> **Current repo state (2026-11-05):** documentation suite + Next.js scaffold only
> (shadcn UI primitives in `src/components/ui`, placeholder Prisma `User`/`Post` models).
> **No application code exists yet** — everything below describes the M0+ build contract
> (PROJECT_MEMORY §2). Split-brain note: this repo builds the Next.js **console** (UI +
> BFF); the appliance-side **Go control plane** (Gin/Fiber REST API + config generators,
> spec'd in the original spec and ADR-002) is out of this repo and simulated here by the
> adapter layer (ADR-004).

Environment contracts: PROJECT_MEMORY §5 (directory map), §11 (sandbox hard rules),
§13 (gotchas). Schema rules: [../03-DATABASE/SCHEMA.md](../03-DATABASE/SCHEMA.md).
UI rules: [../05-FRONTEND/UI_DESIGN_SYSTEM.md](../05-FRONTEND/UI_DESIGN_SYSTEM.md) and
[../05-FRONTEND/PAGE_MAP.md](../05-FRONTEND/PAGE_MAP.md). Build order:
[../01-PRODUCT/ROADMAP.md](../01-PRODUCT/ROADMAP.md) §3.

---

## 1. Environment

Command cheat sheet (details below):

| Task | Command |
|---|---|
| Install deps | `bun install` |
| Dev server (already running in background) | `bun run dev` (port 3000) |
| Lint gate | `bun run lint` |
| Apply schema | `bun run db:push` |
| Seed | `bunx prisma db seed` |
| Seed reset (volatile only) | `bunx prisma db seed -- --reset` |
| Inspect data | `bunx prisma studio` (stop afterwards) |
| Start realtime service | `cd mini-services/realtime-service && bun --hot index.ts` |
| Tail dev log | `tail -n 50 /home/z/my-project/dev.log` |

### 1.1 Session Workflow (start → finish)

1. Read `docs/README.md` §2 protocol, then `PROJECT_MEMORY.md` (state + contracts).
2. Read only the topic docs your task needs (reading matrix in README §2).
3. Confirm the dev server is up (`tail dev.log`); start the realtime service if your
   task touches realtime views.
4. Make schema changes first (if any): SCHEMA.md → `prisma/schema.prisma` → `db:push` →
   seed if needed → update DB docs.
5. Build backend (API routes via `lib/api/handler.ts`), then wire views/hooks.
6. Verify: `bun run lint` → exercise flows in the browser → tail `dev.log`.
7. Update every doc your change invalidated + ROADMAP §4 tracker if a milestone moved.
8. Append the session log entry (PROJECT_MEMORY §15) — including dependency
   justifications and any open questions for the next session.

| Item | Value / rule |
|---|---|
| Runtime | Bun (no Node directly, no npm/yarn/pnpm) |
| Install | `bun install` at repo root |
| Dev server | `bun run dev` — Next.js on **port 3000**, runs in background; the script tees output to `/home/z/my-project/dev.log` |
| Logs | Tail `dev.log` (never read the whole file) when anything misbehaves |
| Lint | `bun run lint` (eslint over the repo) — MUST pass before declaring work done |
| Build | **NEVER run `bun run build`** in the sandbox (standalone-output copying breaks the running dev setup; there is no production deploy here) |
| Tests | No test framework. Verification = `bun run lint` + clean `dev.log` + exercising flows in the browser |
| One instance | Never start a second dev server; port 3000 is already owned by the background process |

## 2. Database

| Step | Command / rule |
|---|---|
| Schema source of truth | `docs/03-DATABASE/SCHEMA.md` §3 — copy the Prisma block **verbatim** into `prisma/schema.prisma` (the file currently holds scaffold `User`/`Post` models until M0 replaces it) |
| Apply schema | `bun run db:push` (runs `prisma db push --accept-data-loss` — intended in sandbox; there are no migrations) |
| Client | `import { db } from '@/lib/db'` — the singleton; never `new PrismaClient()` elsewhere |
| Seed | `bunx prisma db seed` (idempotent; configured via `prisma.seed` in package.json at M0) |
| Datasource URL | SCHEMA.md pins `url = "file:../db/cryptsk.db"`. The current scaffold file uses `env("DATABASE_URL")` — M0 replaces it; do not "fix" SCHEMA.md to match the scaffold |
| Seed reset | `bunx prisma db seed -- --reset` — wipes volatile tables (logs/events/sessions/leases), keeps config + audit (DATA_LIFECYCLE §5) |
| Inspect | `bunx prisma studio` — but **stop it afterwards**; a running studio can hold the SQLite lock and stall API writes ("db locked" symptoms) |
| After schema edits | Update `docs/03-DATABASE/SCHEMA.md` + `ER_DIAGRAM.md` in the same task (README §4 same-task rule) |
| File location | Database file is `db/cryptsk.db` (relative to repo root, per the datasource `file:../db/cryptsk.db` from `prisma/`); do not create second databases for experiments — use `--reset` instead |

## 3. Services and Ports

| Service | Port | Start | Notes |
|---|---|---|---|
| Next.js (UI + `/api/v1`) | 3000 | `bun run dev` (background, always on) | Logs to `dev.log` |
| Realtime mini-service | 3003 | `bun --hot index.ts` inside `mini-services/realtime-service/` | Own `package.json`; must print its listening line at boot; **must be started for any realtime view to work** |
| Current state | — | — | At the time of writing the folder is a `.gitkeep`-only scaffold; M0 creates the real service per §10 |

Gateway rules (hard constraints — PROJECT_MEMORY §11):

- All browser requests use **relative URLs only** — no absolute hosts, no ports in
  hostnames.
- Cross-service traffic goes through the gateway via the `?XTransformPort=` **query
  parameter**.
- The socket.io connect string is **exactly**:

  ```ts
  io("/?XTransformPort=3003")
  ```

  Never `io("http://localhost:3003")`, never a path variant. The mini-service binds
  0.0.0.0 so the gateway can reach it.

## 4. Project Layout (Condensed)

Full map: PROJECT_MEMORY §5 (authoritative — do not duplicate here). Skeleton:

```
src/app/page.tsx            THE only route (renders AppShell)
src/app/api/v1/**           all API route handlers (envelope/auth/RBAC/audit via lib/api)
src/components/{ui,shell,views,charts,shared}
src/lib/{db,auth,api,adapters,engine,validators}
src/hooks/                  one file per resource (TanStack Query)
mini-services/realtime-service/   socket.io hub, port 3003, own package.json
prisma/schema.prisma        copy of docs/03-DATABASE/SCHEMA.md §3
db/cryptsk.db               SQLite file
dev.log                     dev server log (tail when debugging)
```

## 5. Coding Standards

| Area | Rule |
|---|---|
| TypeScript | Strict mode; no `any` in new code (zod infers shapes); types in `src/types/` |
| Interactivity | `"use client"` on every component using state/hooks/socket/zustand (Next 16 + React 19 requirement — PROJECT_MEMORY §13) |
| Components | Interactive components live in `src/components/{shell,views,charts,shared}`; primitives stay in `src/components/ui` (shadcn — reuse, do not rebuild) |
| Data hooks | One file per resource (`src/hooks/use-firewall-rules.ts`), TanStack Query with fully-parameterized query keys `[resource, params]` |
| Validation | zod **everywhere at the edges**: API request bodies, DB JSON-string fields, adapter payloads; reuse enum values from `lib/validators/enums.ts` (PROJECT_MEMORY §6) |
| Errors | API responses go through the envelope (`lib/api/envelope.ts`): success `{data, meta?}` / error `{error:{code,message,details?}}`; route handlers never hand-roll auth/audit — they call `lib/api/handler.ts` |
| Logging | No `console.log` left behind (lint config as-is catches stray debug code; remove temp logs before finishing) |
| Tests | No test files, no test framework — lint + logs + browser is the loop |
| File naming | kebab-case TS files: `use-firewall-rules.ts`, `rule-editor.tsx`, `envelope.ts`; view folders per module: `src/components/views/firewall/` |
| ESLint | `eslint.config.mjs` stays as-is; `bun run lint` clean is a DoD gate |

## 6. UI Rules (Recap)

Detail: UI_DESIGN_SYSTEM + PAGE_MAP (linked at top). Non-negotiables:

| Rule | Value |
|---|---|
| Component source | shadcn/ui first; extend, never re-implement primitives |
| Colors | **No indigo, no blue anywhere** (components, charts, docs examples); brand emerald; semantic emerald/amber/rose for allow/warn/block; neutrals zinc |
| Spacing | Cards `p-4`/`p-6`, grids `gap-4`/`gap-6` |
| Long lists | `max-h-96 overflow-y-auto` + custom scrollbar styles (logs, tables) |
| Touch targets | min 44px on mobile controls |
| Footer | Sticky bottom pattern `min-h-screen flex flex-col` + `mt-auto` wherever a footer exists (never overlays content) |
| Motion | framer-motion, subtle only (150–250 ms), respect reduced-motion |
| Theme | dark default, light available (next-themes, class strategy) |
| Raw JSON | never render raw JSON blobs — use `JsonFieldViewer` (monospace, collapsible) |

## 7. Adding Dependencies

- Allowed **only with a documented reason** (PROJECT_MEMORY §11.15): the reason goes in
  the session log entry for that task.
- Before assuming anything is installed, **check `package.json`**. Currently *not yet*
  installed but expected during M0: `socket.io`, `socket.io-client`, `jose`, `bcryptjs`.
  Already present: recharts, zustand, @tanstack/react-query + react-table, zod,
  react-hook-form, framer-motion, @dnd-kit/*, sonner, next-themes, date-fns.
- Pin the version (`bun add <pkg>@<version>`); avoid packages that duplicate existing
  stack choices (e.g. no `axios` — use `fetch`; no moment — `date-fns` exists).

## 8. Debug Playbook

| Symptom | First action | Then |
|---|---|---|
| Blank page / view does not render | `tail -n 50 /home/z/my-project/dev.log` for compile/runtime errors | Open browser console; check the hash view is registered in `view-registry.ts` |
| 401 loops / login works then bounces | Check the `cryptsk_token` cookie exists and the JWT secret env is stable across restarts | Decode the token (exp/role/tenantId claims); hit `/api/v1/auth/me` and inspect the envelope |
| Socket silent (no `metrics:tick`) | Is the mini-service running? (`bun --hot` in `mini-services/realtime-service/`) — it prints a listening line at boot | Confirm the connect string is **exactly** `io("/?XTransformPort=3003")`; confirm `subscribe {channels:["metrics",...]}` was sent |
| Gateway 404 / transform error on fetch | Verify the request used a **relative** URL and `?XTransformPort=` for cross-service calls | Absolute URLs or host:port fetches are sandbox violations — fix the fetch, not the gateway |
| "Database locked" errors | Stop `prisma studio` / stray prisma processes holding the SQLite file | Retry the request; if persistent, restart the dev server (single-instance rule) |
| Stale data after a mutation | Confirm the mutation path broadcast `config:updated {section}` | Check the query invalidation key prefix matches the resource (`["firewall-rules"]` etc., PROJECT_MEMORY §13) |
| Charts render wrong colors / no data | Check the chart goes through `components/charts/` wrappers with the locked palette (no indigo/blue) | Confirm query key + envelope shape in the network tab |
| Everything broken after schema edit | Re-run `bun run db:push`; confirm `prisma/schema.prisma` still matches SCHEMA.md verbatim | Seed if tables are empty; restart dev server once |
| Lint failures unrelated to your change | Fix them only if trivial; otherwise note them in the session log | Never disable rules to pass lint |

## 9. Definition of Done (Any Task)

1. `bun run lint` passes (zero errors, no new warnings).
2. `dev.log` shows no new errors after exercising the changed flows.
3. Core flows verified in the browser (per `AGENTS.md`): the changed views render,
   mutations persist, realtime views update — on the single route `/` with hash deep
   links (refresh-safe).
4. Docs updated in the same task (README §4 same-task rule): module doc status, API docs
   for endpoint changes, SCHEMA/ER for schema changes, ROADMAP §4 tracker for milestone
   status.
5. Session log appended to PROJECT_MEMORY §15 (newest on top, dated, lists what changed
   and why — including any new dependency justification).

"Not done" is the default state of anything you cannot verify with this checklist —
partial work is fine, unverified work is not. Mark the ROADMAP §4 tracker `IN PROGRESS`
with a sub-step note rather than leaving it silently half-done.

## 10. Mini-Service Development

Layout of `mini-services/realtime-service/`:

```
mini-services/realtime-service/
├── package.json    own bun project (independent deps, e.g. socket.io only here)
└── index.ts        entry; started with `bun --hot index.ts`
```

Rules:

| Rule | Detail |
|---|---|
| Fixed port | 3003 (hard-coded); bind 0.0.0.0 so the gateway can forward |
| Boot line | MUST print a listening line at startup (e.g. `realtime-service listening on 3003`) — debugging + gateway logs depend on it |
| Hot reload | Develop with `bun --hot`; process restarts on save |
| No DB access | The mini-service keeps **no database connection**; it polls the Next internal endpoint `GET /api/internal/events?cursor=N` every 1 s for ring-buffer events (single-writer to SQLite; SIMULATION_LAYER §7) |
| Events | Emits only the locked set from PROJECT_MEMORY §7.3; payloads identical to the table there |
| Gateway forwarding | Browser → gateway → service via `?XTransformPort=3003`; the service answers on any Host (no hostname checks) |

Checklist for shipping a change to the realtime service:

1. Event name/payload change? PROJECT_MEMORY §7.3 edited first (contracts are locked).
2. Boot line still prints; port still 3003; bind still 0.0.0.0.
3. Poll cursor logic still resumes from last event after restart (no replay storms).
4. No DB connection introduced (single-writer rule).
5. Browser reconnect verified: kill and restart the service while a dashboard view is
   open — socket.io should reconnect and resume ticks without a page reload.

Adding a future mini-service (same pattern): new folder under `mini-services/<name>/`
with its own `package.json` and fixed unique port, `bun --hot` entry that prints a
listening line, gateway access exclusively via `?XTransformPort=<port>`, and an ADR/
PROJECT_MEMORY contract note documenting its endpoints or events **before** code (docs
first). Realtime-adjacent features must never be replaced by SSE or polling inside Next
(sandbox rule 6).
