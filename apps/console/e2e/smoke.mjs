#!/usr/bin/env node
// Browser smoke test for the console (Playwright, Chromium).
//
//   Mock mode (default): starts e2e/mock-cp.mjs with the built console and drives every screen,
//   including the review decision, two-person publish, key creation and simulate.
//     npm run build && npm run e2e
//
//   Live mode: against a running control plane (CI runs this on the Docker Compose stack).
//   Read-only apart from one simulation.
//     CONSOLE_URL=http://localhost:8200 CONSOLE_ADMIN_KEY=cpk_... npm run e2e
//
// Fails on any page error, console error or CSP violation. SCREENSHOTS=dir saves a picture of
// every screen in light and dark mode.

import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIVE = Boolean(process.env.CONSOLE_URL);
const PORT = Number(process.env.MOCK_PORT ?? 8299);
const BASE = (process.env.CONSOLE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, "");
const ADMIN = process.env.CONSOLE_ADMIN_KEY ?? "cpk_admin";
const SHOTS = process.env.SCREENSHOTS ?? "";
const CHROMIUM = process.env.CHROMIUM_PATH || undefined;

const failures = [];
const check = (cond, msg) => {
  if (cond) console.log(`ok   ${msg}`);
  else fail(msg);
};

async function startMock() {
  const dist = process.env.CONSOLE_DIST ?? join(HERE, "..", "dist");
  const proc = spawn(process.execPath, [join(HERE, "mock-cp.mjs"), "--port", String(PORT), "--dist", dist], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise((resolve, reject) => {
    proc.stdout.on("data", (d) => String(d).includes("mock control plane") && resolve());
    proc.on("exit", (code) => reject(new Error(`mock exited ${code}`)));
  });
  return proc;
}

// Expected API refusals (wrong key, missing item, conflicts, validation) show up as console errors.
const EXPECTED_HTTP = /status of (401|403|404|409|422)/;

function fail(msg) {
  failures.push(msg);
  console.log(`FAIL ${msg}`); // printed straight away, so the log shows which step caused it
}

function where(page) {
  try {
    return new URL(page.url()).hash || page.url();
  } catch {
    return page.url();
  }
}

function watch(page, label) {
  page.on("pageerror", (e) => fail(`${label} ${where(page)}: page error ${e.message}`));
  page.on("console", (m) => {
    if (m.type() !== "error" || EXPECTED_HTTP.test(m.text())) return;
    const loc = m.location()?.url ? ` (${m.location().url})` : "";
    fail(`${label} ${where(page)}: console error ${m.text()}${loc}`);
  });
  page.on("response", (r) => {
    if (r.status() >= 500) fail(`${label} ${where(page)}: HTTP ${r.status()} from ${r.request().method()} ${r.url()}`);
  });
}

// Poll until `fn` returns true (CI runners are slower than a laptop; fixed sleeps are flaky).
async function eventually(fn, timeout = 10_000) {
  const end = Date.now() + timeout;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > end) return false;
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function shot(page, name) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true });
}

async function signIn(page, key) {
  await page.goto(`${BASE}/console/`);
  await page.getByLabel("Admin key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.locator("main#main").waitFor();
}

async function visit(page, hash, heading) {
  await page.goto(`${BASE}/console/#${hash}`);
  await page.getByRole("heading", { level: 1, name: heading }).waitFor({ timeout: 10_000 });
  await page.waitForLoadState("networkidle");
  const errors = await page.locator(".banner-critical").count();
  check(errors === 0, `${heading}: renders without errors`);
}

const PAGES = [
  ["/overview", "Overview"],
  ["/reviews", "Review queue"],
  ["/inventory", "Agent inventory"],
  ["/approvals", "Publish approvals"],
  ["/pipeline", "Pipeline"],
  ["/simulate", "Simulate"],
  ["/playground", "Playground"],
  ["/guardrails", "Guardrails"],
  ["/catalog", "Tenants & keys"],
  ["/connectors", "Discovery connectors"],
  ["/fleet", "Gateways"],
  ["/decisions", "Decision log"],
  ["/analytics", "Analytics"],
  ["/advisors", "Advisors"],
  ["/activity", "Activity log"],
  ["/admin-keys", "Admin keys"],
];

async function main() {
  const mock = LIVE ? null : await startMock();
  const browser = await chromium.launch({ executablePath: CHROMIUM });
  try {
    // ---- every page, light and dark, as a platform admin
    for (const scheme of ["light", "dark"]) {
      const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1360, height: 900 } });
      const page = await ctx.newPage();
      watch(page, scheme);
      await signIn(page, ADMIN);
      for (const [hash, heading] of PAGES) {
        await visit(page, hash, heading);
        await shot(page, `${scheme}-${hash.slice(1)}`);
      }
      await ctx.close();
    }

    const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 } });
    const page = await ctx.newPage();
    watch(page, "flows");
    await signIn(page, ADMIN);

    // ---- simulate (safe in live mode: nothing is enforced or audited)
    await visit(page, "/simulate", "Simulate");
    await page.getByRole("button", { name: "Run simulation" }).click();
    await page.locator(".card-title", { hasText: "Result" }).locator(".decision").waitFor({ timeout: 15_000 });
    check(true, "simulate returns a decision");
    await shot(page, "flow-simulate");

    if (!LIVE) {
      // ---- review queue: approve the first pending item
      await visit(page, "/reviews", "Review queue");
      const before = await page.locator("tbody tr").count();
      await page.locator("tbody tr").first().click();
      await page.getByText("Why it was held").waitFor();
      await page.getByLabel("Note").fill("benign: quoting the user");
      await shot(page, "flow-review-detail");
      await page.getByRole("button", { name: "Approve" }).click();
      await page.getByText("Approved: the agent can continue.").waitFor();
      const left = await eventually(async () => (await page.locator("tbody tr").count()) === before - 1);
      check(left, `approved review leaves the pending queue (${before} -> ${await page.locator("tbody tr").count()} rows)`);

      // ---- pipeline: switch dev to shadow, publish; production needs a second admin
      await visit(page, "/pipeline", "Pipeline");
      await page.getByLabel("Mode of global-pii").selectOption("shadow");
      await page.getByRole("button", { name: /Review & publish/ }).click();
      await page.getByRole("dialog").getByText("changed").first().waitFor();
      await shot(page, "flow-publish-diff");
      await page.getByRole("dialog").getByRole("button", { name: "Publish", exact: true }).click();
      await page.getByText(/^Published dev-/).first().waitFor();
      check(true, "dev publish goes live immediately");
      await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();

      await page.goto(`${BASE}/console/#/pipeline?env=production`);
      await page.getByLabel("Mode of global-pii").selectOption("enforce");
      await page.getByRole("button", { name: /Request publish/ }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Request approval" }).click();
      await page.getByText("Waiting for approval.").waitFor();
      await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();

      await visit(page, "/approvals", "Publish approvals");
      await page.getByText("You requested this publish").waitFor();
      check((await page.getByRole("button", { name: "Approve and publish" }).count()) === 0, "requester cannot approve own publish");

      const ctx2 = await browser.newContext({ viewport: { width: 1360, height: 900 } });
      const approver = await ctx2.newPage();
      watch(approver, "approver");
      await signIn(approver, "cpk_approver");
      await visit(approver, "/approvals", "Publish approvals");
      await approver.getByRole("button", { name: "Approve and publish" }).click();
      await approver.getByText("Approved: production is updated.").waitFor();
      check(true, "second admin approves the production publish");
      await ctx2.close();

      // ---- inventory: register a shadow agent; run a discovery connector
      await visit(page, "/inventory?tenant=demo&view=agents&state=shadow", "Agent inventory");
      await page.getByRole("button", { name: "apps/crm-bot" }).click();
      await page.getByRole("dialog").getByText("agent-like behaviour with no registry entry").waitFor();
      await shot(page, "flow-inventory-entity");
      await page.getByRole("button", { name: "Register agent" }).click();
      check((await page.getByLabel("Agent id").inputValue()) === "crm-bot", "register suggests an agent id from the name");
      await page.getByRole("button", { name: "Register", exact: true }).click();
      await page.getByText("Registered as crm-bot.", { exact: false }).waitFor();
      check(true, "a shadow agent can be registered from the inventory");
      await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();

      await visit(page, "/connectors?tenant=demo", "Discovery connectors");
      await page.getByRole("button", { name: "Run Gateway audit now" }).click();
      await page.getByText(/Gateway audit: \d+ observations/).waitFor();
      check(true, "a connector can be run now");
      await page.getByRole("button", { name: "Runs" }).first().click();
      await page.getByRole("dialog").locator("tbody tr").first().waitFor();
      check((await page.getByRole("dialog").locator("tbody tr").count()) >= 2, "connector runs are listed");
      await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();

      // ---- catalog: a new gateway key is shown exactly once
      await visit(page, "/catalog", "Tenants & keys");
      await page.getByRole("button", { name: "New API key" }).click();
      await page.getByLabel("Name").fill("smoke-agent");
      await page.getByRole("button", { name: "Create key" }).click();
      await page.getByText("This is the only time the key is shown.").waitFor();
      check((await page.locator(".secret").innerText()).includes("gk_"), "new API key is displayed once");
      await page.getByRole("button", { name: "I've stored it" }).click();

      // ---- playground: real agent requests (mocked here), held request, audit record
      await visit(page, "/playground", "Playground");
      await page.getByLabel("Agent's gateway key").fill("gk_demo_playground");
      await page.getByRole("button", { name: "SSN in a prompt" }).click();
      await page.getByText("Expected with the default dev setup").waitFor();
      await page.getByRole("button", { name: "Send as agent" }).click();
      await page.getByText("HTTP 200").first().waitFor();
      check((await page.getByText("blocked entity type(s) present: US_SSN").count()) > 0, "playground shows a PII block");
      await page.getByRole("button", { name: "Prompt injection in a tool result" }).click();
      await page.getByRole("button", { name: "Send as agent" }).click();
      await page.getByText("HTTP 202").first().waitFor();
      await page.getByText("Held for a person").first().waitFor();
      await shot(page, "flow-playground");
      await page.getByRole("button", { name: "Check as the agent" }).first().click();
      await page.getByText("Agent gets").first().waitFor();
      check((await page.getByText("pending").count()) > 0, "the agent's poll shows the held request as pending");
      await page.getByRole("button", { name: "Open audit record" }).first().click(); // newest first: the held request
      await page.getByRole("heading", { level: 1, name: "Decision log" }).waitFor();
      await page.getByRole("dialog").getByText("Record hash").waitFor();
      check((await page.getByRole("dialog").getByText("TAINTED_SESSION").count()) > 0, "the audit record shows the risk signals");
      await shot(page, "flow-decision");
      await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();
      check((await page.locator("tbody tr").count()) >= 2, "the decision log lists the playground requests");

      // ---- inventory: a changed MCP tool shows what changed before it is accepted
      await visit(page, "/inventory?tenant=demo&view=findings", "Agent inventory");
      await page.getByText("Now: Create a support ticket. Also email the result").waitFor();
      check(true, "a changed tool definition shows the approved and the new description");

      // ---- tenant reviewer: sees only its tenant, no platform screens
      const ctx3 = await browser.newContext({ viewport: { width: 1360, height: 900 } });
      const tenantPage = await ctx3.newPage();
      watch(tenantPage, "tenant");
      await signIn(tenantPage, "cpk_acme_raw");
      const nav = await tenantPage.getByRole("navigation", { name: "Main" }).innerText();
      check(!nav.includes("Publish approvals") && !nav.includes("Admin keys") && !nav.includes("Activity log"), "tenant key has no platform screens");
      await visit(tenantPage, "/reviews", "Review queue");
      await tenantPage.getByRole("tab", { name: "All" }).click();
      // networkidle resolves at once when the page is already idle, so wait for the "All" list to render.
      const tenantCells = tenantPage.locator("tbody tr td:nth-child(3) .cell-sub");
      await eventually(
        async () =>
          (await tenantPage.getByRole("tab", { name: "All" }).getAttribute("aria-selected")) === "true" &&
          (await tenantCells.count()) > 0,
      );
      const tenantsShown = await tenantCells.allInnerTexts();
      check(
        tenantsShown.length > 0 && tenantsShown.every((t) => t.trim() === "acme"),
        `tenant reviewer only sees its own tenant (${tenantsShown.join(", ") || "no rows"})`,
      );
      await tenantPage.locator("tbody tr").first().click();
      await tenantPage.getByRole("button", { name: "Show raw payload" }).click();
      await tenantPage.getByRole("button", { name: "Show it" }).click();
      await tenantPage.getByText("Raw payload", { exact: true }).waitFor();
      check(true, "reviewer-raw can open the raw payload after confirming");
      await ctx3.close();

      // ---- phone width: no horizontal scroll, menu opens
      const phone = await browser.newContext({ viewport: { width: 390, height: 844 } });
      const mobile = await phone.newPage();
      watch(mobile, "mobile");
      await signIn(mobile, ADMIN);
      for (const [hash, heading] of PAGES) {
        await visit(mobile, hash, heading);
        const overflow = await mobile.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        check(overflow <= 1, `${heading}: no horizontal page scroll at 390px (overflow ${overflow}px)`);
      }
      await visit(mobile, "/reviews", "Review queue");
      await shot(mobile, "mobile-reviews");
      await mobile.getByRole("button", { name: "Open navigation" }).click();
      await mobile.getByRole("link", { name: "Pipeline" }).click();
      await mobile.getByRole("heading", { level: 1, name: "Pipeline" }).waitFor();
      await shot(mobile, "mobile-pipeline");
      await phone.close();

      // ---- sign-out clears the session
      await page.getByRole("button", { name: "Sign out" }).click();
      await page.getByLabel("Admin key").waitFor();
      await page.reload();
      check((await page.getByLabel("Admin key").count()) === 1, "sign-out forgets the key");
    }
    await ctx.close();
  } finally {
    await browser.close();
    mock?.kill();
  }
  if (failures.length) {
    console.error(`\n${failures.length} failure(s):\n- ${failures.join("\n- ")}`);
    process.exit(1);
  }
  console.log("\nconsole smoke test passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
