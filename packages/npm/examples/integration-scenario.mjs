// Copyright Foxlin Industries. Local JSON-lines integration example, no secrets in output.
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createHash } from "node:crypto";
import { AegirIntegrationClient, FileAuthorizationJournal, AegirMfaRequired, AegirIntegrationError } from "../dist/esm/index.js";
let client, journal, ticket;
try {
  const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const binding = createHash("sha256").update(JSON.stringify([config.apiBaseUrl, config.organizationId, config.applicationId])).digest("hex");
  journal = new FileAuthorizationJournal(config.journalPath, binding);
  client = new AegirIntegrationClient({ ...config, journal });
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    let input;
    try {
      input = JSON.parse(line);
      let result;
      if (input.op === "authenticate") {
        try {
          const session = await client.authenticate(config.username, config.password, input.challengeId, input.totpCode);
          ticket = session.accessToken; result = { authenticated: true };
        } catch (error) {
          ticket = undefined;
          if (error instanceof AegirMfaRequired) result = { authenticated: false, mfaRequired: true, challengeId: error.challengeId };
          else throw error;
        }
      } else if (input.op === "reconnect") result = await client.reconnect();
      else if (input.op === "poll") result = await client.poll(undefined, input.acknowledge !== false);
      else if (input.op === "check") result = await client.authorize(ticket ?? "", input.operation);
      else if (input.op === "execute") {
        let effects = 0;
        result = { ...await client.execute(ticket ?? "", input.operation, () => { effects++; }), effects };
      } else if (input.op === "disconnect") { await client.disconnect(); result = { connected: false }; }
      else if (input.op === "state") result = journal.inspect();
      else if (input.op === "close") { client.close(); journal.close(); result = { closed: true }; }
      else throw new AegirIntegrationError("unknown_command");
      process.stdout.write(JSON.stringify({ requestId: input.requestId ?? null, ok: true, ...result }) + "\n");
      if (input.op === "close") break;
    } catch (error) {
      process.stdout.write(JSON.stringify({ requestId: input?.requestId ?? null, ok: false,
        error: error instanceof AegirIntegrationError ? error.code : "integration_failure" }) + "\n");
    }
  }
} catch (error) {
  process.stdout.write(JSON.stringify({ requestId: null, ok: false,
    error: error instanceof AegirIntegrationError ? error.code : "configuration_failure" }) + "\n");
  process.exitCode = 1;
} finally { client?.close(); journal?.close(); ticket = undefined; }

