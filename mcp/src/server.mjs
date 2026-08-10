import { stdin, stdout } from "node:process";
import { createClient, createJsonRpcError, createJsonRpcSuccess, handleMessage, narrowCredentials } from "./core.mjs";

async function main() {
  const client = createClient();

  // Trade the long-lived developer key for a scope-narrowed token before serving anything.
  await narrowCredentials(client);
  let buffer = "";

  stdin.setEncoding("utf8");
  stdin.on("data", async (chunk) => {
    buffer += chunk;
    let newlineIndex = buffer.indexOf("\n");

    while (newlineIndex >= 0) {
      const raw = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      newlineIndex = buffer.indexOf("\n");

      if (!raw) {
        continue;
      }

      const message = JSON.parse(raw);

      try {
        const result = await handleMessage(client, message);
        stdout.write(`${JSON.stringify(createJsonRpcSuccess(message.id, result))}\n`);
      } catch (error) {
        stdout.write(`${JSON.stringify(createJsonRpcError(message.id, error))}\n`);
      }
    }
  });
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  main();
}

export { handleMessage } from "./core.mjs";
