# Awaaz

A cybersecurity hackathon platform designed to give college students a safe, structured way to report ragging or harassment anonymously and track committee action using a Case ID.

> **Current Status:** Initial frontend project setup only. Supabase database persistence, authentication, and backend security controls are **not** connected yet, and no encryption is claimed in this initial scaffold.

## Tech Stack

- **Framework:** Next.js (App Router)
- **UI Library:** React
- **Language:** TypeScript (strict mode)
- **Styling:** Tailwind CSS v4
- **Icons:** Lucide React
- **Planned Backend:** Supabase (to be integrated in the next phase)

## Routes

| Route | Purpose |
| --- | --- |
| `/` | Landing page introducing Awaaz, design principles, and reporting flow |
| `/report` | Anonymous complaint intake form UI (client-side validation only) |
| `/track` | Case ID lookup UI and planned review lifecycle template |
| `/committee/login` | Committee portal sign-in UI (pending Supabase Auth) |
| `/committee/dashboard` | Committee triage dashboard shell and integration hooks |
| `/about` | Project mission, tech stack, and phased roadmap |

## Project Structure

```text
awaaz/
├── eslint.config.mjs
├── next.config.ts
├── package.json
├── postcss.config.mjs
├── README.md
├── tsconfig.json
└── src/
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
        └── constants.ts
```

## Getting Started

1. Ensure Node.js LTS and npm are installed.
2. Install dependencies (if not already installed):

   ```bash
   npm install
   ```

3. Start the development server:

   ```bash
   npm run dev
   ```

   *(On Windows PowerShell if script execution is restricted, use `npm.cmd run dev`.)*

4. Open `http://localhost:3000` in your browser.

## Available Scripts

- `npm run dev` — Start the Next.js development server
- `npm run build` — Create an optimized production build
- `npm run start` — Serve the production build locally
- `npm run lint` — Run ESLint checks
- `npm run typecheck` — Run TypeScript type checking (`tsc --noEmit`)
