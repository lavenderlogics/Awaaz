export interface NavItem {
  label: string;
  href: string;
}

export const NAV_LINKS: NavItem[] = [
  { label: "Home", href: "/" },
  { label: "Report Incident", href: "/report" },
  { label: "Track Case", href: "/track" },
  { label: "About", href: "/about" },
];

export const INCIDENT_CATEGORIES = [
  "Ragging / Hazing",
  "Verbal Harassment or Threats",
  "Physical Intimidation or Assault",
  "Cyberbullying / Digital Harassment",
  "Hostel or Campus Misconduct",
  "Other Safety Concern",
] as const;

export const PLANNED_CASE_STAGES = [
  {
    id: "submitted",
    label: "Submitted",
    description: "Report logged into the intake queue with a reference Case ID.",
  },
  {
    id: "under_review",
    label: "Under Review",
    description: "Assigned to authorized campus committee members for triage.",
  },
  {
    id: "action_initiated",
    label: "Action Initiated",
    description: "Preliminary inquiry or campus safety intervention underway.",
  },
  {
    id: "resolved",
    label: "Resolved",
    description: "Final outcome recorded and closure note posted for the Case ID.",
  },
] as const;

export const URGENCY_LEVELS = [
  { value: "standard", label: "Standard Review" },
  { value: "elevated", label: "Elevated Safety Concern" },
  { value: "immediate", label: "Immediate Campus Risk" },
] as const;
