# AGENTS.md — AI Agent Entry Point

**Project:** Cryptsk UTM/NGFW Console (Next.js 16, TypeScript, Prisma/SQLite)

## Read BEFORE writing any code — in this order:

1. `docs/README.md` — index + AI agent protocol + reading-order matrix
2. `docs/00-PROJECT-MEMORY/PROJECT_MEMORY.md` — project state, contracts, conventions,
   sandbox constraints, gotchas. **This file is the single source of truth.**
3. Only the topic docs your task requires (matrix in `docs/README.md`).

## Non-negotiable sandbox constraints (full list in PROJECT_MEMORY §11):

- The ONLY user-visible route is `/` (`src/app/page.tsx`). Never create other Next.js routes.
  All "pages" are client-side views selected by hash (e.g. `#/firewall/rules`).
- Fetch only relative URLs. Cross-service requests use `?XTransformPort=<port>` (never a port in the hostname).
- Realtime = socket.io mini-service on port 3003 (`mini-services/realtime-service/`).
- `z-ai-web-dev-sdk` is backend-only. Never import it in client code.
- No `bun run build`. Dev server: `bun run dev` (port 3000, logs in `dev.log`). Lint: `bun run lint`.
- DB: edit `prisma/schema.prisma` then `bun run db:push`. Client: `import { db } from '@/lib/db'`.
- Use existing shadcn/ui components in `src/components/ui`. No indigo/blue colors.
- Sticky footer, responsive, accessible. No test code.

## When done with a task:

Append a dated entry to `docs/00-PROJECT-MEMORY/PROJECT_MEMORY.md` §15 (Session Log)
and update any doc your change invalidated. Docs win over code.
