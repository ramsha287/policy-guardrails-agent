#!/usr/bin/env node
// `npm run dev:mock`: the mock control plane on :8200 plus the Vite dev server (works on Windows too).
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mock = spawn(process.execPath, [join(here, "mock-cp.mjs"), "--port", "8200"], { stdio: "inherit" });
const vite = spawn("npx", ["vite"], { stdio: "inherit", shell: true, cwd: join(here, "..") });
const stop = () => {
  mock.kill();
  vite.kill();
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
vite.on("exit", (code) => {
  mock.kill();
  process.exit(code ?? 0);
});
