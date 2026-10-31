import { Link } from "react-router-dom";
import { WebActivityDashboard } from "../components/web/WebActivityDashboard";
import { EmptyState, ErrorPanel, linkButtonClass, Spinner } from "../components/ui/feedback";
import { useAnalysis } from "../state/AnalysisContext";
import { PageHeader } from "./Placeholder";

/** Domains / Web Activity: per-domain traffic and latency for the capture currently loaded in PCAP Analysis. */
export function WebActivity() {
  const { session } = useAnalysis();
  return (
    <>
      <PageHeader title="Domains / Web Activity" subtitle="Which sites were contacted, how much traffic they carried, and how responsive the connections were." />
      {session.phase === "idle" && (
        <EmptyState title="No capture loaded" action={<Link to="/analysis" className={linkButtonClass("primary")}>Open PCAP Analysis</Link>}>
          Analyze a capture to see the domains it contacted.
        </EmptyState>
      )}
      {(session.phase === "uploading" || session.phase === "analyzing") && <Spinner label="Analyzing the capture…" />}
      {session.phase === "error" && (
        <ErrorPanel title="The analysis failed" actions={<Link to="/analysis" className={linkButtonClass()}>Back to PCAP Analysis</Link>}>{session.problem.message}</ErrorPanel>
      )}
      {session.phase === "ready" && (session.bundle.analysis.packet_statistics.total_packets === 0
        ? <EmptyState title="This capture contains no packets">There is no web activity to show.</EmptyState>
        : <WebActivityDashboard analysisId={session.bundle.job.id} />)}
    </>
  );
}
