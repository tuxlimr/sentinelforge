import type { ReactNode } from "react";

export function Loading() {
  return (
    <div className="stack">
      <div className="skeleton" />
      <div className="skeleton" />
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="error" role="alert">
      {message}. Is the API running? Start it with <code>sentinelforge serve</code>.
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
