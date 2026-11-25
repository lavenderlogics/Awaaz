# Awaaz

A cybersecurity hackathon platform designed to give college students a safe, structured way to report ragging or harassment anonymously and track committee action using a Case ID.

> **Current Status:** Next.js App Router frontend connected to **Supabase** (`@supabase/supabase-js` + `@supabase/ssr`) for client/server sessions and committee authentication. No client-side encryption is claimed in this setup.

## Tech Stack

- **Framework:** Next.js (App Router)
- **UI Library:** React
- **Language:** TypeScript (strict mode)
- **Styling:** Tailwind CSS v4
- **Icons:** Lucide React
- **Backend & Auth:** Supabase (`@supabase/supabase-js`, `@supabase/ssr`)

## Routes

| Route | Purpose |
| --- | --- |
| `/` | Landing page introducing Awaaz, design principles, and reporting flow |
| `/report` | Anonymous complaint intake form UI (client-side validation; awaiting column mapping for `complaints`) |
| `/track` | Case ID lookup UI and planned review lifecycle template |
| `/committee/login` | Committee portal sign-in wired to Supabase Auth |
| `/committee/dashboard` | Committee triage dashboard wired to Supabase Auth & `complaints` query when signed in |
| `/about` | Project mission, tech stack, and phased roadmap |

## Environment Configuration

Supabase keys are stored in `.env.local` (ignored by Git). See `.env.example` for the expected variables:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-supabase-publishable-or-anon-key
```

## Project Structure

```text
awaaz/
├── .env.example
├── .gitignore
├── eslint.config.mjs
├── next.config.ts
├── package.json
├── postcss.config.mjs
├── README.md
├── tsconfig.json
└── src/
    ├── proxy.ts
    ├── app/
    │   ├── about/page.tsx
    │   ├── committee/
    │   │   ├── dashboard/page.tsx
    │   │   └── login/page.tsx
    │   ├── report/page.tsx
    │   ├── track/page.tsx
    │   ├── globals.css
    │   ├── layout.tsx
    │   └── page.tsx
    ├── components/
    │   ├── layout/
    │   │   ├── Footer.tsx
    │   │   └── Navbar.tsx
    │   ├── sections/
    │   │   ├── CommitteeDashboardClient.tsx
    │   │   ├── CommitteeLoginForm.tsx
    │   │   ├── ReportForm.tsx
    │   │   └── TrackCaseClient.tsx
    │   └── ui/
    │       ├── Badge.tsx
    │       ├── Button.tsx
    │       ├── Card.tsx
    │       ├── FormField.tsx
    │       ├── PageHeader.tsx
    │       ├── SectionHeader.tsx
    │       └── StatusNotice.tsx
    └── lib/
        ├── constants.ts
        └── supabase/
            ├── client.ts
            ├── config.ts
            ├── proxy.ts
            └── server.ts
```

## Getting Started

1. Ensure Node.js LTS and npm are installed.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env.local` and fill in your Supabase URL and publishable/anon key.
4. Start the development server:

   ```bash
   npm run dev
   ```

   *(On Windows PowerShell if script execution is restricted, use `npm.cmd run dev`.)*

5. Open `http://localhost:3000` in your browser.
