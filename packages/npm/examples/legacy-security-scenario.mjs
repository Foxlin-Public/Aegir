// Foxlin Industries. Run only against an approved synthetic local installation.
// Private configuration is read from a file; credentials and response bodies never reach stdout.
import { readFileSync } from "node:fs";
import { AegirSecurityClient } from "../dist/esm/index.js";

let client, operation = "configuration";
const emit = ok => console.log(JSON.stringify({ op: operation, ok }));
async function run(op, action) { operation = op; const value = await action(); emit(true); return value; }
try {
  const bytes = readFileSync(process.argv[2]);
  if (bytes.length > 65536) throw new Error("invalid configuration");
  const config = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (typeof config.subjectId !== "string" || !config.subjectId.trim()) throw new Error("invalid configuration");
  client = new AegirSecurityClient({ baseUrl: config.apiBaseUrl, developerKey: config.developerKey,
    expectedSubjectId: config.subjectId, certificateSha256: config.certificateSha256,
    timeoutMs: config.timeoutMs ?? 10000 });
  await run("scan", () => client.scanIdentity(config.subjectId));
  await run("graph", () => client.getIdentityGraph(config.subjectId));
  await run("graphJson", () => client.getIdentityGraphJson(config.subjectId));
  await run("exposure", () => client.getExposureSummary(config.subjectId));
  const action = await run("action", () => client.performAction({ subjectId: config.subjectId,
    actionType: "RequestClarity", reason: "Synthetic local SDK contract exercise" }));
  await run("reverse", () => client.reverseAction(action.actionId, "Synthetic local SDK contract exercise"));
  await run("history", () => client.getActionHistory(config.subjectId));
} catch { emit(false); process.exitCode = 1; }
finally { client?.close(); }
