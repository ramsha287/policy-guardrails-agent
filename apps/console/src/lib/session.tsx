// Sign-in with an admin key. The key lives in sessionStorage only (cleared when the tab closes),
// is sent as X-Admin-Key to this origin, and is dropped as soon as the API answers 401.

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

import { Api, ApiError } from "./api";
import type { Me, Permission } from "./types";

const STORAGE_KEY = "guardrail-console.admin-key";

function readStoredKey(): string | null {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeKey(key: string | null): void {
  try {
    if (key) window.sessionStorage.setItem(STORAGE_KEY, key);
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // storage blocked: the session just won't survive a reload
  }
}

export interface Session {
  api: Api;
  me: Me;
  can: (permission: Permission) => boolean;
  signOut: (reason?: string) => void;
}

const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const s = useContext(SessionContext);
  if (!s) throw new Error("useSession outside SessionProvider");
  return s;
}

export interface AuthState {
  session: Session | null;
  restoring: boolean;
  notice: string | null;
  signIn: (key: string) => Promise<void>;
  restore: () => Promise<void>;
}

export function useAuth(): AuthState {
  const [key, setKey] = useState<string | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [restoring, setRestoring] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);

  const signOut = useCallback((reason?: string) => {
    storeKey(null);
    setKey(null);
    setMe(null);
    setNotice(reason ?? null);
  }, []);

  const api = useMemo(
    () => (key ? new Api(key, undefined, () => signOut("Your admin key was rejected. Sign in again.")) : null),
    [key, signOut],
  );

  const signIn = useCallback(async (candidate: string) => {
    const trimmed = candidate.trim();
    const probe = new Api(trimmed);
    try {
      const who = await probe.me();
      storeKey(trimmed);
      setKey(trimmed);
      setMe(who);
      setNotice(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) throw new Error("That key is not valid, or it was revoked.");
      throw e;
    }
  }, []);

  const restore = useCallback(async () => {
    const stored = readStoredKey();
    if (stored) {
      try {
        await signIn(stored);
      } catch {
        storeKey(null);
      }
    }
    setRestoring(false);
  }, [signIn]);

  const session = useMemo<Session | null>(
    () =>
      api && me
        ? {
            api,
            me,
            can: (permission) => me.permissions.includes(permission),
            signOut,
          }
        : null,
    [api, me, signOut],
  );

  return { session, restoring, notice, signIn, restore };
}

export function SessionProvider({ session, children }: { session: Session; children: ReactNode }) {
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}
