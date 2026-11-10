// Reads config.json into the environment, then does one batch. The seed comes only from the QBIT_SEED secret.
import { readFileSync } from "node:fs";
Object.assign(process.env, JSON.parse(readFileSync(new URL("./config.json", import.meta.url), "utf8")));
const { run } = await import("./clerk/clerk.mjs");
try {
  const r = await run({ send: process.argv.includes("--send") });
  if (r.busy) console.log("busy; the next run will try again");
} catch (e) { console.error("clerk:", e.message); process.exitCode = 1; }
