import { useEffect, useState, type ReactNode } from "react";

import { IconMenu, IconMoon, IconShield, IconSignOut, IconSun } from "./components/icons";
import { ToastProvider } from "./components/toast";
import { Loading } from "./components/ui";
import { useResource } from "./lib/hooks";
import { navigate, useRoute } from "./lib/router";
import { SessionProvider, useAuth, useSession } from "./lib/session";
import type { Permission } from "./lib/types";
import { ActivityPage } from "./pages/Activity";
import { AdminKeysPage } from "./pages/AdminKeys";
import { AnalyticsPage } from "./pages/Analytics";
import { ApprovalsPage } from "./pages/Approvals";
import { CatalogPage } from "./pages/Catalog";
import { FleetPage } from "./pages/Fleet";
import { GuardrailsPage } from "./pages/Guardrails";
import { OverviewPage } from "./pages/Overview";
import { PipelinePage } from "./pages/Pipeline";
import { ReviewsPage } from "./pages/Reviews";
import { SignIn } from "./pages/SignIn";
import { SimulatePage } from "./pages/Simulate";

interface NavItem {
  path: string;
  label: string;
  group: "Operate" | "Configure" | "Observe";
  visible: (s: ReturnType<typeof useSession>) => boolean;
  render: () => ReactNode;
}

const can = (p: Permission) => (s: ReturnType<typeof useSession>) => s.can(p);
const platform = (s: ReturnType<typeof useSession>) => s.me.platform;

const NAV: NavItem[] = [
  { path: "/overview", label: "Overview", group: "Operate", visible: can("read"), render: () => <OverviewPage /> },
  { path: "/reviews", label: "Review queue", group: "Operate", visible: can("read"), render: () => <ReviewsPage /> },
  {
    path: "/approvals",
    label: "Publish approvals",
    group: "Operate",
    visible: (s) => s.me.platform && (s.can("publish:request") || s.can("publish:approve") || s.can("read")),
    render: () => <ApprovalsPage />,
  },
  { path: "/pipeline", label: "Pipeline", group: "Configure", visible: can("read"), render: () => <PipelinePage /> },
  {
    path: "/simulate",
    label: "Simulate",
    group: "Configure",
    visible: (s) => s.can("read") && s.me.features.simulate,
    render: () => <SimulatePage />,
  },
  { path: "/guardrails", label: "Guardrails", group: "Configure", visible: can("read"), render: () => <GuardrailsPage /> },
  { path: "/catalog", label: "Tenants & keys", group: "Configure", visible: can("read"), render: () => <CatalogPage /> },
  { path: "/fleet", label: "Gateways", group: "Observe", visible: can("read"), render: () => <FleetPage /> },
  {
    path: "/analytics",
    label: "Analytics",
    group: "Observe",
    visible: (s) => s.can("read") && s.me.features.analytics,
    render: () => <AnalyticsPage />,
  },
  { path: "/activity", label: "Activity log", group: "Observe", visible: platform, render: () => <ActivityPage /> },
  {
    path: "/admin-keys",
    label: "Admin keys",
    group: "Observe",
    visible: can("admin-keys:write"),
    render: () => <AdminKeysPage />,
  },
];

type Theme = "system" | "light" | "dark";
const THEME_KEY = "guardrail-console.theme";

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = window.localStorage.getItem(THEME_KEY);
      return t === "light" || t === "dark" ? t : "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      // per-viewer convenience only
    }
  }, [theme]);
  const cycle = () => setTheme((t) => (t === "system" ? "dark" : t === "dark" ? "light" : "system"));
  return [theme, cycle];
}

function Shell() {
  const session = useSession();
  const route = useRoute();
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, cycleTheme] = useTheme();
  const items = NAV.filter((n) => n.visible(session));
  const active = items.find((n) => route.path === n.path || route.path.startsWith(`${n.path}/`)) ?? items[0];

  useEffect(() => {
    if (route.path === "/" && items[0]) navigate(items[0].path);
    setMenuOpen(false);
  }, [route.path]); // eslint-disable-line react-hooks/exhaustive-deps

  const pendingReviews = useResource(
    () => session.api.reviews({ status: "pending" }).then((r) => r.length),
    [session.api],
    15_000,
  );
  const pendingRequests = useResource(
    () =>
      session.me.platform
        ? session.api.publishRequests({ status: "pending" }).then((r) => r.length)
        : Promise.resolve(0),
    [session.api],
    30_000,
  );
  const counts: Record<string, number | undefined> = {
    "/reviews": pendingReviews.data,
    "/approvals": pendingRequests.data,
  };

  const groups: NavItem["group"][] = ["Operate", "Configure", "Observe"];
  const themeLabel = theme === "system" ? "Theme: system" : theme === "dark" ? "Theme: dark" : "Theme: light";

  return (
    <div className="shell">
      <div className="topbar">
        <button type="button" className="icon-btn" aria-label="Open navigation" onClick={() => setMenuOpen(true)}>
          <IconMenu size={18} />
        </button>
        <strong>{active?.label ?? "Guardrail Console"}</strong>
        <span />
      </div>
      {menuOpen && <div className="scrim" onClick={() => setMenuOpen(false)} />}
      <nav className={menuOpen ? "sidebar open" : "sidebar"} aria-label="Main">
        <div className="brand">
          <span className="brand-mark">
            <IconShield size={16} />
          </span>
          <span>
            Guardrails
            <small>Control plane console</small>
          </span>
        </div>
        {groups.map((g) => {
          const inGroup = items.filter((i) => i.group === g);
          if (inGroup.length === 0) return null;
          return (
            <div key={g}>
              <p className="nav-group">{g}</p>
              {inGroup.map((i) => {
                const count = counts[i.path];
                return (
                  <a
                    key={i.path}
                    href={`#${i.path}`}
                    className="nav-link"
                    aria-current={active?.path === i.path ? "page" : undefined}
                  >
                    <span>{i.label}</span>
                    {count ? (
                      <span className="nav-count" aria-label={`${count} pending`}>
                        {count}
                      </span>
                    ) : null}
                  </a>
                );
              })}
            </div>
          );
        })}
        <div className="sidebar-footer">
          <div className="identity">
            {session.me.name}
            <small>
              {session.me.roles.join(", ")} · {session.me.tenant_id ? `tenant ${session.me.tenant_id}` : "platform"}
            </small>
          </div>
          <div className="sidebar-actions">
            <button type="button" className="icon-btn" aria-label={themeLabel} title={themeLabel} onClick={cycleTheme}>
              {theme === "light" ? <IconSun size={16} /> : <IconMoon size={16} />}
            </button>
            <button
              type="button"
              className="icon-btn"
              aria-label="Sign out"
              title="Sign out"
              onClick={() => session.signOut()}
            >
              <IconSignOut size={16} />
            </button>
          </div>
        </div>
      </nav>
      <main className="main" id="main">
        {active ? active.render() : <p>This key has no access to the console.</p>}
      </main>
    </div>
  );
}

export function App() {
  const auth = useAuth();
  useEffect(() => {
    void auth.restore();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (auth.restoring) return <Loading label="Signing in" />;
  if (!auth.session) return <SignIn onSignIn={auth.signIn} notice={auth.notice} />;
  return (
    <SessionProvider session={auth.session}>
      <ToastProvider>
        <Shell />
      </ToastProvider>
    </SessionProvider>
  );
}
