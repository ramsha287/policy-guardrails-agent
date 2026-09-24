// Shared building blocks. Styling lives in styles.css (tokens + light/dark), never inline.

import {
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";

import { ApiError } from "../lib/api";
import type { Decision, PublishRequestStatus, ReviewStatus } from "../lib/types";
import { IconAlert, IconCheck, IconClock, IconCopy, IconInfo, IconX } from "./icons";

// ---- buttons ------------------------------------------------------------------------------------

type Variant = "primary" | "secondary" | "danger" | "ghost";

export function Button({
  variant = "secondary",
  size = "md",
  busy = false,
  icon,
  children,
  className,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm" | "md";
  busy?: boolean;
  icon?: ReactNode;
}) {
  return (
    <button
      type="button"
      className={["btn", `btn-${variant}`, size === "sm" ? "btn-sm" : "", className ?? ""].join(" ").trim()}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy ? <span className="spinner" aria-hidden="true" /> : icon}
      {children && <span>{children}</span>}
    </button>
  );
}

// ---- badges ---------------------------------------------------------------------------------------

export type Tone = "neutral" | "info" | "good" | "warning" | "serious" | "critical";

const TONE_ICON: Partial<Record<Tone, ReactNode>> = {
  good: <IconCheck size={12} />,
  warning: <IconClock size={12} />,
  serious: <IconAlert size={12} />,
  critical: <IconX size={12} />,
  info: <IconInfo size={12} />,
};

/** Status chip: tone color + icon + label, so state never relies on color alone. */
export function Badge({ tone = "neutral", children, icon = true }: { tone?: Tone; children: ReactNode; icon?: boolean }) {
  return (
    <span className={`badge badge-${tone}`}>
      {icon && TONE_ICON[tone]}
      <span>{children}</span>
    </span>
  );
}

/** A decision keeps the same color everywhere in the console (charts, tables, badges). */
export function DecisionBadge({ decision }: { decision: Decision | string }) {
  return (
    <span className="decision">
      <span className={`decision-dot decision-${decision}`} aria-hidden="true" />
      <span>{decision}</span>
    </span>
  );
}

const REVIEW_TONE: Record<ReviewStatus, Tone> = {
  pending: "warning",
  approved: "good",
  rejected: "critical",
  expired: "neutral",
};
export function ReviewStatusBadge({ status }: { status: ReviewStatus }) {
  return <Badge tone={REVIEW_TONE[status]}>{status}</Badge>;
}

const REQUEST_TONE: Record<PublishRequestStatus, Tone> = {
  pending: "warning",
  approved: "good",
  rejected: "critical",
  expired: "neutral",
  stale: "neutral",
};
export function RequestStatusBadge({ status }: { status: PublishRequestStatus }) {
  return <Badge tone={REQUEST_TONE[status]}>{status}</Badge>;
}

export function ModeBadge({ mode }: { mode: "enforce" | "shadow" }) {
  return <span className={`mode mode-${mode}`}>{mode}</span>;
}

// ---- layout -----------------------------------------------------------------------------------------

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Card({
  title,
  actions,
  children,
  className,
  flush = false,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  return (
    <section className={`card ${flush ? "card-flush" : ""} ${className ?? ""}`.trim()}>
      {(title || actions) && (
        <div className="card-header">
          {title && <h2 className="card-title">{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="toolbar">{children}</div>;
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" /> {label}…
    </div>
  );
}

/** An API error with its details (validation errors, warnings). */
export function ErrorBanner({ error, title }: { error: Error | undefined | null; title?: string }) {
  if (!error) return null;
  const details = error instanceof ApiError ? error.errors : [];
  const warnings = error instanceof ApiError ? error.warnings : [];
  const forbidden = error instanceof ApiError && error.status === 403;
  return (
    <div className="banner banner-critical" role="alert">
      <IconAlert size={16} />
      <div>
        <p className="banner-title">{title ?? (forbidden ? "Not allowed" : "Something went wrong")}</p>
        <p>{error.message}</p>
        {details.length > 0 && (
          <ul className="banner-list">
            {details.map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>
        )}
        {warnings.length > 0 && (
          <ul className="banner-list">
            {warnings.map((d, i) => (
              <li key={i}>Warning: {d}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warning" | "good"; children: ReactNode }) {
  const icon = tone === "good" ? <IconCheck size={16} /> : tone === "warning" ? <IconAlert size={16} /> : <IconInfo size={16} />;
  return (
    <div className={`banner banner-${tone}`} role="status">
      {icon}
      <div>{children}</div>
    </div>
  );
}

// ---- forms ------------------------------------------------------------------------------------------

export function Field({
  label,
  hint,
  children,
  htmlFor,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string; count?: number }[];
  onChange: (value: T) => void;
  label: string;
}) {
  return (
    <div className="segmented" role="tablist" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="tab"
          aria-selected={o.value === value}
          className={o.value === value ? "segmented-item active" : "segmented-item"}
          onClick={() => onChange(o.value)}
        >
          {o.label}
          {o.count !== undefined && <span className="segmented-count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

// ---- dialog -----------------------------------------------------------------------------------------

/** Native <dialog>: focus handling, Esc to close and a real modal backdrop for free. */
export function Dialog({
  open,
  title,
  onClose,
  children,
  footer,
  wide = false,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className={wide ? "dialog dialog-wide" : "dialog"}
      aria-labelledby={titleId}
      onClose={onClose}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <div className="dialog-header">
        <h2 id={titleId}>{title}</h2>
        <button type="button" className="icon-btn" aria-label="Close" onClick={onClose}>
          <IconX size={16} />
        </button>
      </div>
      <div className="dialog-body">{open && children}</div>
      {footer && <div className="dialog-footer">{footer}</div>}
    </dialog>
  );
}

// ---- misc ---------------------------------------------------------------------------------------------

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      variant="ghost"
      icon={done ? <IconCheck size={14} /> : <IconCopy size={14} />}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          window.setTimeout(() => setDone(false), 1500);
        } catch {
          // clipboard blocked: the value is still selectable on screen
        }
      }}
    >
      {done ? "Copied" : label}
    </Button>
  );
}

export function Json({ value, maxHeight }: { value: unknown; maxHeight?: "sm" | "md" }) {
  return (
    <pre className={`json ${maxHeight ? `json-${maxHeight}` : ""}`.trim()}>{JSON.stringify(value, null, 2)}</pre>
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="mono">{children}</code>;
}
