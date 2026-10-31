import { useNavigate } from "react-router-dom";
import { Button } from "../ui/feedback";
import { useInvestigation } from "../../state/InvestigationContext";

/** The one-click entry point. Clicking is the explicit action that lets PacketMind send a summary of the measurements to Gemini. */
export function InvestigateButton({ analysisId, size = "normal" }: { analysisId: string; size?: "normal" | "large" }) {
  const { run, state } = useInvestigation();
  const navigate = useNavigate();
  const busy = state.phase === "running";
  const go = () => { navigate("/investigation"); void run(analysisId, true); };
  return (
    <Button variant="primary" disabled={busy} onClick={go} className={size === "large" ? "px-5 py-2.5 text-base" : ""}>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
      Investigate Network
    </Button>
  );
}
