// Copyright Foxlin Industries. Protocol-unit and isolated negative startup evidence, not backend authority acceptance.
import test from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { parseFrame,readFrames,MAX_INPUT } from "../src/wire.mjs";
import { handleMessage,createJsonRpcError } from "../src/core.mjs";
const request={jsonrpc:"2.0",id:1,method:"tools/list"};
test("genuine SDK semantic code maps safely without server detail",()=>{
 const result=createJsonRpcError(1,{code:"cross_tenant_denied",message:"SyntheticSensitiveServerDetail"});
 assert.equal(result.error.code,-32000);assert.equal(result.error.message,"Aegir rejected the request (cross_tenant_denied).");assert.ok(!JSON.stringify(result).includes("SyntheticSensitiveServerDetail"));
});
test("actual UTF8 parser accepts bounded canonical request",()=>assert.deepEqual(parseFrame(Buffer.from(JSON.stringify(request))),request));
for(const [name,source] of [
  ["empty",""],["invalid-json","{"],["null","null"],["batch","[]"],
  ["duplicate-id",'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}'],
  ["duplicate-nested",'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_identity","arguments":{"subjectId":"a","subjectId":"b"}}}'],
  ["wrong-version",JSON.stringify({...request,jsonrpc:"1.0"})],
  ["null-id",JSON.stringify({...request,id:null})],["fractional-id",JSON.stringify({...request,id:1.5})],
  ["boolean-id",JSON.stringify({...request,id:false})],["empty-id",JSON.stringify({...request,id:""})],
  ["unsafe-id",JSON.stringify({...request,id:Number.MAX_SAFE_INTEGER+1})],
  ["long-id",JSON.stringify({...request,id:"a".repeat(129)})],
  ["unknown-field",JSON.stringify({...request,authority:"platform"})],
  ["response-form",'{"jsonrpc":"2.0","id":1,"result":{}}'],
  ["array-params",JSON.stringify({...request,params:[]})],
  ["deep-params",JSON.stringify({...request,params:{x:JSON.parse("[".repeat(17)+"0"+"]".repeat(17))}})],
  ["large-collection",JSON.stringify({...request,params:{x:new Array(129).fill(1)}})]
])test("rejects "+name,()=>assert.throws(()=>parseFrame(Buffer.from(source)),e=>[-32700,-32600].includes(e.code)));
test("rejects invalid UTF8 without replacement",()=>assert.throws(()=>parseFrame(Buffer.from([0xff,0xfe])),e=>e.code===-32700));
test("rejects oversized frame",()=>assert.throws(()=>parseFrame(Buffer.alloc(MAX_INPUT+1,32))));
test("chunked framing preserves separate request identities",async()=>{
  const text=JSON.stringify(request)+"\n"+JSON.stringify({...request,id:"two"})+"\n";
  const frames=[];for await(const f of readFrames(Readable.from([Buffer.from(text.slice(0,7)),Buffer.from(text.slice(7))])))frames.push(f);
  assert.deepEqual(frames.map(x=>x.message.id),[1,"two"]);
});
test("oversized frame is discarded then next valid frame parses",async()=>{
  const frames=[];for await(const f of readFrames(Readable.from([Buffer.alloc(MAX_INPUT+5,32),Buffer.from("\n"+JSON.stringify(request)+"\n")])))frames.push(f);
  assert.equal(frames[0].error.code,-32600);assert.equal(frames[1].message.id,1);
});
test("EOF partial message has a parse error",async()=>{
  const frames=[];for await(const f of readFrames(Readable.from([Buffer.from('{"id":')])) )frames.push(f);
  assert.equal(frames[0].error.code,-32700);
});
test("tool schema rejects inherited prototype property names",async()=>{
  await assert.rejects(handleMessage({},{method:"tools/call",params:{name:"account_summary",arguments:{toString:"secret"}}}));
  await assert.rejects(handleMessage({},{method:"tools/call",params:{name:"scan_identity",arguments:{subjectId:"x",toString:"secret"}}}),e=>e.code===-32602);
});
for(const mode of ["delegated","invalid"])
  test("isolated actual process refuses "+mode+" before ambient authority",async()=>{
    const environment={SystemRoot:process.env.SystemRoot,PATH:process.env.PATH,TEMP:process.env.TEMP,
      AEGIR_BASE_URL:"https://127.0.0.1:1/apis",AEGIR_DEVELOPER_KEY:"synthetic-key:do-not-reflect-this-secret",
      AEGIR_MCP_EXPECTED_DEVELOPER_ID:"dev_synthetic",AEGIR_MCP_CREDENTIAL_MODE:mode};
    await assert.rejects(promisify(execFile)(process.execPath,[fileURLToPath(new URL("../src/server.mjs",import.meta.url))],{env:environment,timeout:10000}),e=>{
      assert.equal(e.code,1);assert.equal(e.stdout,"");assert.match(e.stderr,/current authority is required/);
      assert.ok(!e.stderr.includes("do-not-reflect"));return true;
    });
  });
