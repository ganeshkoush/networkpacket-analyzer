import type { Severity } from "../api/types";

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

// Full class names (Tailwind needs them statically). Colors are always paired with a text label.
export const SEVERITY_STYLE: Record<Severity, { text: string; bg: string; dot: string; border: string; var: string }> = {
  CRITICAL: { text: "text-sev-critical", bg: "bg-sev-critical/15", dot: "bg-sev-critical", border: "border-sev-critical/40", var: "var(--color-sev-critical)" },
  HIGH: { text: "text-sev-high", bg: "bg-sev-high/15", dot: "bg-sev-high", border: "border-sev-high/40", var: "var(--color-sev-high)" },
  MEDIUM: { text: "text-sev-medium", bg: "bg-sev-medium/15", dot: "bg-sev-medium", border: "border-sev-medium/40", var: "var(--color-sev-medium)" },
  LOW: { text: "text-sev-low", bg: "bg-sev-low/15", dot: "bg-sev-low", border: "border-sev-low/40", var: "var(--color-sev-low)" },
  INFO: { text: "text-sev-info", bg: "bg-sev-info/15", dot: "bg-sev-info", border: "border-sev-info/40", var: "var(--color-sev-info)" },
};

export function countBySeverity(findings: { severity: Severity }[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/** "PORT_SCAN" -> "Port scan". */
export function typeLabel(type: string): string {
  const s = type.toLowerCase().replace(/_/g, " ");
  return (s.charAt(0).toUpperCase() + s.slice(1))
    .replace(/\bdns\b/i, "DNS").replace(/\barp\b/i, "ARP").replace(/\btcp\b/i, "TCP")
    .replace(/\bsyn\b/i, "SYN").replace(/\bnxdomain\b/i, "NXDOMAIN")
    .replace(/\bdga like\b/i, "DGA-like").replace(/\btunneling like\b/i, "tunneling-like");
}
