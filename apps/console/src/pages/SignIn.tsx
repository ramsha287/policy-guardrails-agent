import { useState, type FormEvent } from "react";

import { IconShield } from "../components/icons";
import { Button, Field, Notice } from "../components/ui";

export function SignIn({ onSignIn, notice }: { onSignIn: (key: string) => Promise<void>; notice: string | null }) {
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!key.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await onSignIn(key);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="signin">
      <form className="signin-card" onSubmit={submit}>
        <span className="brand-mark">
          <IconShield size={16} />
        </span>
        <h1>Guardrail Console</h1>
        <p className="lead">Sign in with your control-plane admin key. What you can see and do follows its roles.</p>
        {notice && <Notice tone="warning">{notice}</Notice>}
        <Field label="Admin key" htmlFor="admin-key" hint="Kept for this browser tab only and sent to this server alone.">
          <input
            id="admin-key"
            className="input"
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder="cpk_…"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            autoFocus
          />
        </Field>
        {error && (
          <p className="banner banner-critical" role="alert">
            {error}
          </p>
        )}
        <Button type="submit" variant="primary" busy={busy} disabled={!key.trim()}>
          Sign in
        </Button>
      </form>
    </div>
  );
}
