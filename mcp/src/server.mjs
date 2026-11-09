import { stdin, stdout } from "node:process";
import { pathToFileURL } from "node:url";
import { once } from "node:events";
import { createJsonRpcError, createJsonRpcSuccess, handleMessage, prepareExecutionClient } from "./core.mjs";
import { readFrames, protocolError, MAX_OUTPUT } from "./wire.mjs";

async function main() {
  const authority=await prepareExecutionClient();
  const ids=new Set();let state="new",active=null;
  async function emit(value) {
    let text=JSON.stringify(value);
    if(Buffer.byteLength(text)>MAX_OUTPUT)text=JSON.stringify(createJsonRpcSuccess(value.id,{isError:true,content:[{type:"text",text:"Output limit exceeded; an operation may have completed. Reconcile before retrying."}]}));
    else authority.assertSafeOutput(value);
    if(!stdout.write(text+"\n"))await once(stdout,"drain");
  }
  try {
    // At most one executing request and no work queue. The reader stays responsive to
    // cancellation; busy requests are refused rather than accumulating effects in memory.
    for await(const frame of readFrames(stdin)) {
      if(frame.error){await emit(createJsonRpcError(null,frame.error));continue;}
      const message=frame.message;
      if(!("id"in message)) {
        if(message.method==="notifications/initialized" && state==="initialized")state="ready";
        if(message.method==="notifications/cancelled" && active && active.method!=="initialize" &&
            typeof message.params?.requestId===typeof active.id && message.params.requestId===active.id) {
          active.cancelled=true;state="faulted";authority.client.close();
        }
        // Notifications never execute tools or emit their own response. Cancellation aborts
        // pending backend IO and quarantines this process; it never proves an effect rolled back.
        continue;
      }
      const identity=typeof message.id+":"+message.id;
      if(ids.has(identity)){await emit(createJsonRpcError(message.id,protocolError(-32600)));continue;}
      if(ids.size>=4096){await emit(createJsonRpcError(message.id,protocolError(-32600)));break;}
      ids.add(identity);
      if(active){await emit(createJsonRpcError(message.id,protocolError(-32600)));continue;}
      const entry={id:message.id,method:message.method,cancelled:false,task:null};active=entry;
      entry.task=(async()=>{
        const deadline=setTimeout(()=>{entry.cancelled=true;state="faulted";authority.client.close();},30000);
        try {
          await authority.requireCurrent();
          if(entry.cancelled)throw protocolError(-32800);
          if(message.method==="initialize") {
            if(state!=="new" || message.params?.protocolVersion!=="2025-03-26" ||
                !message.params.clientInfo || typeof message.params.clientInfo.name!=="string" || typeof message.params.clientInfo.version!=="string" ||
                !message.params.capabilities || typeof message.params.capabilities!=="object" || Array.isArray(message.params.capabilities))throw protocolError(-32602);
            state="initialized";
          } else if(state!=="ready" && message.method!=="ping")throw protocolError(-32600);
          const result=await handleMessage(authority.client,message);
          if(entry.cancelled)throw protocolError(-32800);
          await emit(createJsonRpcSuccess(message.id,result));
        } catch(error) {
          // A connection failure may follow an already committed backend effect.
          // Quarantine this process as with cancellation; never silently reuse its
          // execution context or imply that a timeout rolled anything back.
          if(error?.code==="transport_error"){state="faulted";authority.client.close();}
          if(entry.cancelled)await emit(createJsonRpcError(message.id,protocolError(-32800)));
          else if(message.method==="tools/call" && ![-32700,-32600,-32601,-32602].includes(error?.code))
            await emit(createJsonRpcSuccess(message.id,{isError:true,content:[{type:"text",text:"Tool could not complete; an effect may have occurred. Reconcile before retrying."}]}));
          else await emit(createJsonRpcError(message.id,error));
        } finally {clearTimeout(deadline);if(active===entry)active=null;}
      })();
      entry.task.catch(()=>{state="faulted";authority.client.close();process.exitCode=1;});
    }
    if(active)await active.task;
  } finally {if(active)await active.task;authority.client.close();}
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(()=>{process.stderr.write("MCP startup or transport failed; current authority is required.\n");process.exitCode=1;});
}

export { handleMessage } from "./core.mjs";
