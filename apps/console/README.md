# Guardrail Console

The operator console for the control plane, including the **human review UI** for ESCALATE
decisions. React + TypeScript, built with Vite into static files that the control plane serves
at `/console` (and `/review` redirects to the review queue). There is no separate server.

| Group | Screen | For |
| --- | --- | --- |
| Operate | Overview | What needs attention: held requests, publishes to approve, unhealthy gateways, last 24 h |
| | Review queue | Approve or reject held requests before they expire (reviewer roles) |
| | Publish approvals | Second-person approval of production publishes and rollbacks |
| | Agent inventory | Discovered agents by state, coverage, findings (with MCP tool changes); register, link, ignore, accept |
| Configure | Pipeline | Assignments per environment, shadow/enforce toggles, diff, publish, rollback |
| | Simulate | Dry-run a request through a draft or the live pipeline on a real gateway (not enforced, not audited) |
| | Playground | Send a real, audited agent request through the gateway with an agent's key; scenarios for each security flow |
| | Guardrails | Registered versions, register a `guardrail.yaml`, deprecate |
| | Tenants & keys | Gateway API keys, agent trust, action risk, score modifiers |
| | Discovery connectors | The inventory's sources: add (platform admins), run now, runs |
| Observe | Gateways | Heartbeats: installed guardrails, snapshot and catalog versions, last error |
| | Decision log | The gateway's audit records: outcome, reason codes, risk signals, guardrail results, advisor answers, hash chain |
| | Analytics | Decisions over time, block rate, latency |
| | Advisors | The advisor pilot and the tenants' hosted-advisor data policy |
| | Activity log | The control plane's append-only change log |
| | Admin keys | Keys and roles for the console and the API |

How to use each screen: [docs/console.md](../../docs/console.md).

## Sign-in and security

- Sign in with a control-plane admin key (`cpk_…`). The console calls `GET /cp/v1/me` and only
  shows what that key's roles allow. The API enforces the same rules, so hiding a button is
  never the only protection.
- The key is kept in `sessionStorage` (this tab only) and sent as `X-Admin-Key` to the same origin.
  A 401 signs the user out immediately, for example after the key is revoked.
- The control plane serves the console with a strict CSP (`script-src 'self'`, `connect-src 'self'`,
  `frame-ancestors 'none'`) and no third-party requests: fonts, icons and charts are local.
- Opening a review, and especially its raw payload (`reviewer-raw` only, after a confirmation), is
  written to the control plane's change log (Activity log).
- The Playground's agent key is kept in the page's memory only and sent to `/cp/v1/playground`.

## Develop

```bash
cd apps/console
npm install
npm run dev:mock        # mock control plane on :8200 (keys: cpk_admin, cpk_approver, cpk_viewer,
                        # cpk_acme_reviewer, cpk_acme_raw) + Vite on :5173
# or against a real control plane:
CONTROL_PLANE_URL=http://localhost:8200 npm run dev
```

## Test

```bash
npm run typecheck && npm test          # types + unit tests (vitest)
npm run build && npm run e2e           # Playwright: every screen in light and dark mode, the review
                                       # decision, two-person publish, inventory and connectors, key
                                       # creation, Playground -> held request -> audit record, a tenant
                                       # reviewer's view, phone width (390 px) without sideways scroll
CONSOLE_URL=http://localhost:8200 CONSOLE_ADMIN_KEY=cpk_... npm run e2e   # read-only, live stack
```

CI runs all of these (`console` job) and the live smoke test against the Docker Compose stack
(`e2e` job). There is no committed `package-lock.json` yet, so CI and the image build use
`npm install`; committing one would make builds reproducible with `npm ci`.

## Design notes

- Tokens in `src/styles.css`; light and dark are both designed, and the theme button cycles
  system → dark → light.
- Decisions keep one colour everywhere (allow blue, modify yellow, escalate violet, block red).
  The order was validated for colour-vision deficiency in both modes. Status colours (good,
  warning, serious, critical) are reserved for state and always come with an icon and a label.
- Charts are plain SVG: one axis, hairline grid, a tooltip per column, and a table view with
  the same numbers.
