import { Link } from "react-router-dom";
import { EmptyState, linkButtonClass } from "../components/ui/feedback";
import { PageHeader } from "./Placeholder";

export function NotFound() {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="That page does not exist" action={<Link to="/" className={linkButtonClass("primary")}>Back to dashboard</Link>}>
        The link may be out of date.
      </EmptyState>
    </>
  );
}
