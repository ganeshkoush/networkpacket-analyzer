import { useCallback, useEffect, useState, type ReactNode } from "react";
import { connectBackend } from "../../lib/bootstrap";
import { Button, ErrorPanel, Spinner } from "../ui/feedback";

/** Holds the app back until the desktop shell has a ready backend; shows why if it could not start. */
export function Startup({ children, connect = connectBackend }: { children: ReactNode; connect?: typeof connectBackend }) {
  const [state, setState] = useState<{ phase: "starting" } | { phase: "ready" } | { phase: "failed"; message: string }>({ phase: "starting" });

  const run = useCallback(async (retry: boolean) => {
    setState({ phase: "starting" });
    const r = await connect(retry);
    setState(r.ok ? { phase: "ready" } : { phase: "failed", message: r.message });
  }, [connect]);

  useEffect(() => { void run(false); }, [run]);

  if (state.phase === "ready") return <>{children}</>;
  return (
    <main className="flex h-full items-center justify-center bg-bg p-8 text-ink">
      <div className="w-full max-w-lg">
        {state.phase === "starting" ? (
          <div className="flex items-center justify-center"><Spinner label="Starting PacketMind…" /></div>
        ) : (
          <ErrorPanel title="PacketMind could not start its analysis service"
            actions={<Button variant="primary" onClick={() => void run(true)}>Try again</Button>}>
            <p className="break-words">{state.message}</p>
            <p className="mt-2 text-xs text-ink-3">Your captures and reports are not affected. If this keeps happening, quit and reopen PacketMind, and check the log file named above.</p>
          </ErrorPanel>
        )}
      </div>
    </main>
  );
}
