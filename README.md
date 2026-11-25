# Awaaz

A cybersecurity hackathon platform enabling college students to report ragging or harassment anonymously with **AES-256-GCM** envelope encryption, **2-of-N Shamir + RSA-OAEP** dual-key committee unlocking, encrypted private evidence storage, and SHA-256 hash-chained audit logs.

## Tech Stack

- **Framework:** Next.js (App Router)
- **UI Library:** React & TypeScript
- **Styling:** Tailwind CSS v4 & Lucide React
- **Database, Auth & Private Storage:** Supabase (`@supabase/supabase-js`, `@supabase/ssr`)
- **Cryptography:** Node.js `crypto` (AES-256-GCM, RSA-OAEP-256, HKDF-SHA256, SHA-256) + GF(256) 2-of-N Shamir Secret Sharing

## Environment Configuration

Copy `.env.example` to `.env.local` (never commit `.env.local` or expose `SUPABASE_SERVICE_ROLE_KEY` with `NEXT_PUBLIC_`):

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-supabase-publishable-or-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-or-secret-key
AWAAZ_KEY_SECRET=replace-with-a-long-random-server-secret
```

## API & Page Routes

- `/` — Landing page
- `/report` & `POST /api/complaints` — Rate-limited anonymous intake encrypting payload & evidence before storing in `complaints`, `evidence_files`, `awaaz-evidence`, and `audit_logs`
- `/track`, `POST /api/complaints/track`, `POST /api/evidence` — Anonymous Case ID status lookup and recovery-secret-verified encrypted evidence upload
- `/committee/login` & `/auth/callback` — Committee sign-in, sign-up with email verification, and password recovery
- `/committee/dashboard` — Protected committee workspace wired to `/api/committee/dashboard`, `/api/committee/keys`, `/api/committee/unlock`, `/api/committee/status`, and `/api/committee/audit-logs`
- `/api/health` — Public Supabase connectivity & table/bucket verification endpoint

## Scripts

- `npm run dev` — Start development server (`npm.cmd run dev` on restricted PowerShell)
- `npm run build` — Build production bundle
- `npm run test` — Run AES-256-GCM & Shamir unit tests
- `npm run typecheck` — Run TypeScript type check
- `npm run lint` — Run ESLint
