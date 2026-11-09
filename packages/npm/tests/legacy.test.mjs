// Copyright Foxlin Industries. Adversarial tests of retained public APIs; no real authority.
import assert from "node:assert/strict";
import { AegirSecurityClient, AegirSecurityError } from "../dist/esm/index.js";
const baseUrl="https://example.invalid/apis";
const valid={valid:true,status:"Valid",detail:null};
const denied={valid:false,status:"SignatureInvalid",detail:null};
const token={access_token:"opaque.synthetic.token",token_type:"Bearer",expires_in:1800,expires_at:"2099-01-01T00:00:00Z",scope:"security:read",scopes:["security:read"],tenant_id:"tenant_test",subject:"subject_test"};
let passed=0;
async function test(name,run){await run();passed++;console.log("ok - legacy "+name);}
const fixture=(value,extra={})=>new AegirSecurityClient({baseUrl,allowTrustedCustomTransport:true,fetcher:async()=>new Response(typeof value==="string"?value:JSON.stringify(value),{status:extra.status??200,headers:{"Content-Type":extra.media??"application/json"}}),...extra.options});
await test("unsafe origins reject before credential callback",()=>{
 for(const u of ["http://example.invalid/apis","https://user:pass@example.invalid/apis","https://example.invalid/apis?q=x","https://example.invalid/apis#f","https://example.invalid/a/../apis"])
 assert.throws(()=>new AegirSecurityClient({baseUrl:u,developerKey:"synthetic-secret",allowTrustedCustomTransport:true,fetcher:async()=>{throw Error("must not run");}}),AegirSecurityError);
});
await test("opaque adapters need deliberate trust opt-in",()=>assert.throws(()=>new AegirSecurityClient({baseUrl,fetcher:async()=>new Response("{}")} ),AegirSecurityError));
await test("duplicate escaped security keys reject",async()=>{
 for(const v of ['{"valid":false,"valid":true,"status":"Valid","detail":null}','{"valid":false,"\\u0076alid":true,"status":"Valid","detail":null}'])await assert.rejects(()=>fixture(v).verifyTransactionReceipt({}),AegirSecurityError);
});
await test("contradictory and ill-typed permits reject",async()=>{
 for(const v of [{...valid,status:"SignatureInvalid"},{...valid,valid:1},{...valid,status:"future"}])await assert.rejects(()=>fixture(v).verifyTransactionReceipt({}),AegirSecurityError);
});
await test("negative verification remains ordinary data",async()=>assert.deepEqual(await fixture(denied).verifyTransactionReceipt({}),denied));
await test("wrong JSON media rejects",async()=>{for(const media of ["application/jsonp","text/plain; note=application/json"])await assert.rejects(()=>fixture(valid,{media}).verifyTransactionReceipt({}),AegirSecurityError);});
await test("charset and optional outer fields accepted",async()=>assert.equal((await fixture({...valid,optional:"compatible"},{media:"application/json; charset=utf-8"}).verifyTransactionReceipt({})).valid,true));
await test("malformed deep and excessive collections reject",async()=>{
 for(const v of ["not-json",'{"n":'.repeat(40)+'1'+'}'.repeat(40),JSON.stringify({...valid,n:Array(4097).fill(0)})])await assert.rejects(()=>fixture(v).verifyTransactionReceipt({}),AegirSecurityError);
});
await test("oversized response rejects",async()=>await assert.rejects(()=>fixture(JSON.stringify({...valid,n:"x".repeat(1048577)})).verifyTransactionReceipt({}),AegirSecurityError));
await test("exact status enforced",async()=>await assert.rejects(()=>fixture(valid,{status:201}).verifyTransactionReceipt({}),AegirSecurityError));
await test("invalid active introspection rejects",async()=>{for(const v of [{active:"yes"},{active:true},{active:false,sub:"subject_test"}])await assert.rejects(()=>fixture(v).introspectToken("synthetic"),AegirSecurityError);});
await test("active expired or wrongly bound introspection rejects",async()=>{
 const v={active:true,sub:"subject_test",tenant_id:"tenant_test",exp:1,scopes:[],roles:[]};
 await assert.rejects(()=>fixture(v).introspectToken("synthetic"),AegirSecurityError);
 await assert.rejects(()=>fixture({...v,exp:4070908800},{options:{expectedTenantId:"other"}}).introspectToken("synthetic"),AegirSecurityError);
});
await test("token fields expiry and scope narrowing reject invalid grants",async()=>{
 for(const v of [{...token,expires_at:"2000-01-01T00:00:00Z"},{...token,scopes:["admin:full"],scope:"admin:full"},{...token,subject:null},{...token,token_type:"Basic"}])await assert.rejects(()=>fixture(v).getToken("security:read"),AegirSecurityError);
});
await test("valid server token remains opaque and usable",async()=>assert.equal((await fixture(token).useNarrowedToken("security:read")).access_token,token.access_token));
await test("agent grant subject cannot switch to another principal",async()=>await assert.rejects(()=>fixture(token).useAgentKey("different:synthetic"),AegirSecurityError));
await test("transaction and subject bindings reject substitution",async()=>{
 await assert.rejects(()=>fixture({transactionId:"other",tenantId:"tenant_test",callerPrincipalType:"Agent",callerPrincipalId:"a",declaredAction:"x",authorizationDecision:"Pending",status:"Created"}).getTransaction("expected"),AegirSecurityError);
 await assert.rejects(()=>fixture({subjectId:"other",graph:{},exposure:{}}).scanIdentity("expected"),AegirSecurityError);
});
await test("client and error serialization do not expose credentials",async()=>{
 const logs=[];const c=new AegirSecurityClient({baseUrl,developerKey:"synthetic-private-sentinel",allowTrustedCustomTransport:true,diagnosticsHooks:{log:e=>logs.push(e)},fetcher:async()=>{throw Error("synthetic-private-sentinel");}});
 assert.ok(!JSON.stringify(c).includes("synthetic-private-sentinel"));
 try{await c.introspectToken("synthetic-target");assert.fail();}catch(e){assert.ok(!JSON.stringify(e).includes("synthetic-private-sentinel"));assert.ok(!e.message.includes("synthetic-private-sentinel"));}
 assert.ok(!JSON.stringify(logs).includes("synthetic-private-sentinel"));
});
await test("server error echo is bounded and sanitized",async()=>{
 const c=fixture({error:"forbidden",message:"synthetic-private-sentinel",agentKey:"different-secret"},{status:403,options:{developerKey:"synthetic-private-sentinel"}});
 try{await c.introspectToken("target");assert.fail();}catch(e){assert.equal(e.code,"forbidden");assert.ok(!JSON.stringify(e).includes("synthetic-private-sentinel"));assert.ok(!JSON.stringify(e).includes("different-secret"));}
});
await test("cancelled signal never invokes adapter",async()=>{
 const controller=new AbortController();controller.abort();let calls=0;
 const c=new AegirSecurityClient({baseUrl,signal:controller.signal,allowTrustedCustomTransport:true,fetcher:async()=>{calls++;return new Response(JSON.stringify(valid));}});
 await assert.rejects(()=>c.verifyTransactionReceipt({}),AegirSecurityError);assert.equal(calls,0);
});
await test("timeout and close prevent late token adoption",async()=>{
 const c=new AegirSecurityClient({baseUrl,timeoutMs:20,allowTrustedCustomTransport:true,fetcher:async()=>{await new Promise(r=>setTimeout(r,80));return new Response(JSON.stringify(token),{headers:{"Content-Type":"application/json"}});}});
 await assert.rejects(()=>c.useNarrowedToken("security:read"),AegirSecurityError);c.close();
 await assert.rejects(()=>c.getToken(),AegirSecurityError);assert.equal(c.toJSON().closed,true);
});
console.log("legacy adversarial named checks: "+passed);

await test("canonical numeric identity enums normalize to named public values",async()=>{
 const graph={graphId:"graph:subject_test",nodes:[{nodeType:6}],edges:[],scores:{exposureScore:0,trustScore:1,connectionClarityScore:1},metadata:{}};
 assert.equal((await fixture(graph).getIdentityGraph("subject_test")).nodes[0].nodeType,"User");
 await assert.rejects(()=>fixture({...graph,nodes:[{nodeType:99}]}).getIdentityGraph("subject_test"),AegirSecurityError);
});
await test("named action input uses exact canonical numeric wire value",async()=>{
 let captured;
 const c=new AegirSecurityClient({baseUrl,allowTrustedCustomTransport:true,fetcher:async(u,i)=>{captured=JSON.parse(i.body);return new Response(JSON.stringify({actionId:"synthetic",subjectId:"subject_test",actionType:3,status:1}),{headers:{"Content-Type":"application/json"}});}});
 const action=await c.performAction({subjectId:"subject_test",actionType:"VerifyConnection"});
 assert.equal(captured.actionType,3);assert.equal(action.actionType,"VerifyConnection");assert.equal(action.status,"Completed");
});

await test("malformed score values reject without echoing credentials",async()=>{
 const c=fixture({graphId:"graph:subject_test",nodes:[],edges:[],scores:{exposureScore:"synthetic-private-sentinel",trustScore:1,connectionClarityScore:1}},{options:{developerKey:"synthetic-private-sentinel"}});
 try{await c.getIdentityGraph("subject_test");assert.fail();}catch(e){assert.ok(e instanceof AegirSecurityError);assert.ok(!e.message.includes("synthetic-private-sentinel"));}
});

await test("raw canonical developer and user graph IDs retain numeric enum support",async()=>{
 for(const kind of ["developer","user"]){
  const graph={graphId:`graph:${kind}:raw_subject`,nodes:[{nodeType:kind==="developer"?2:6}],edges:[],scores:{exposureScore:0,trustScore:1,connectionClarityScore:1},metadata:{}};
  assert.equal((await fixture(graph).getIdentityGraph("raw_subject")).nodes[0].nodeType,kind==="developer"?"Developer":"User");
 }
});
await test("canonical exposure has graph binding without an invented subject field",async()=>{
 const graph={graphId:"graph:developer:raw_subject",nodes:[],edges:[],scores:{exposureScore:0,trustScore:1,connectionClarityScore:1},metadata:{}};
 const exposure={graphId:graph.graphId,generatedAtUtc:"2026-10-24T00:00:00Z",exposureScore:0,findings:[],summaryText:"Synthetic"};
 assert.equal((await fixture(exposure).getExposureSummary("raw_subject")).graphId,graph.graphId);
 assert.equal((await fixture({subjectId:"raw_subject",graph,exposure,actionHistory:[]}).scanIdentity("raw_subject")).graph.graphId,graph.graphId);
});
await test("raw subject bindings reject unrelated and mismatched nested graphs",async()=>{
 const graph={graphId:"graph:developer:other_subject",nodes:[],edges:[],scores:{exposureScore:0,trustScore:1,connectionClarityScore:1},metadata:{}};
 await assert.rejects(()=>fixture(graph).getIdentityGraph("raw_subject"),AegirSecurityError);
 await assert.rejects(()=>fixture({graphId:graph.graphId,findings:[]}).getExposureSummary("raw_subject"),AegirSecurityError);
 await assert.rejects(()=>fixture({subjectId:"raw_subject",graph:{...graph,graphId:"graph:developer:raw_subject"},exposure:{graphId:"graph:user:raw_subject",findings:[]},actionHistory:[]}).scanIdentity("raw_subject"),AegirSecurityError);
});
await test("diagnostic promise shares deadline and cannot trigger late token adoption",async()=>{
 let release, calls=0, authorization;
 const hooks={trace:()=>new Promise(resolve=>{release=resolve;})};
 const c=new AegirSecurityClient({baseUrl,accessToken:"old-synthetic-token",timeoutMs:30,diagnosticsHooks:hooks,
  allowTrustedCustomTransport:true,fetcher:async(u,i)=>{calls++;authorization=new Headers(i.headers).get("Authorization");return new Response("[]",{headers:{"Content-Type":"application/json"}});}});
 const started=Date.now();
 try{await assert.rejects(()=>c.useNarrowedToken("security:read"),AegirSecurityError);assert.ok(Date.now()-started<500);assert.equal(calls,0);}
 finally{release?.();hooks.trace=undefined;}
 await new Promise(r=>setTimeout(r,10));assert.equal(calls,0);
 await c.listProviders();assert.equal(authorization,"Bearer old-synthetic-token");c.close();
});
await test("cancel and close interrupt diagnostic waits before any credential request",async()=>{
 for(const mode of ["cancel","close"]){
  let release,calls=0;
  const c=new AegirSecurityClient({baseUrl,timeoutMs:1000,diagnosticsHooks:{trace:()=>new Promise(resolve=>{release=resolve;})},
   allowTrustedCustomTransport:true,fetcher:async()=>{calls++;return new Response(JSON.stringify(token),{headers:{"Content-Type":"application/json"}});}});
  const pending=c.useNarrowedToken("security:read"),timer=setTimeout(()=>mode==="close"?c.close():c.cancelPending(),20);
  try{await assert.rejects(()=>pending,AegirSecurityError);assert.equal(calls,0);}
  finally{clearTimeout(timer);release?.();}
  await new Promise(r=>setTimeout(r,10));assert.equal(calls,0);c.close();
 }
});
await test("diagnostic exceptions stay best effort and sanitized",async()=>{
 const c=fixture([],{options:{diagnosticsHooks:{trace:()=>{throw Error("synthetic-private-diagnostic");},log:()=>Promise.reject(Error("synthetic-private-diagnostic")),metric:()=>{throw Error("synthetic-private-diagnostic");}}}});
 assert.deepEqual(await c.listProviders(),[]);c.close();
});
await test("configured credential components cannot reflect into public errors or diagnostics",async()=>{
 for(const field of ["developerKey","accessToken","configKey"]){
  const id="synthetic_component_id",secret="private_component_marker",events=[];
  for(const reflected of [id,secret]){
   const c=new AegirSecurityClient({baseUrl,[field]:id+":"+secret,allowTrustedCustomTransport:true,
    diagnosticsHooks:{log:e=>events.push(e),trace:e=>events.push(e),metric:e=>events.push(e)},
    fetcher:async()=>new Response(JSON.stringify({error:reflected,correlationId:reflected,detail:"prefix-"+reflected+"-suffix",[reflected]:"value"}),{status:403,headers:{"Content-Type":"application/json","X-Correlation-Id":reflected}})});
   try{await c.introspectToken("synthetic-target");assert.fail();}
   catch(e){assert.ok(e instanceof AegirSecurityError);const visible=JSON.stringify({error:e,message:e.message,events});assert.ok(!visible.includes(id));assert.ok(!visible.includes(secret));assert.equal(e.correlationId,null);}
   finally{c.close();}
  }
 }
});
await test("agent credential secret half cannot become correlation or error metadata",async()=>{
 const id="synthetic_agent_component",secret="private_agent_component",events=[];
 const c=new AegirSecurityClient({baseUrl,allowTrustedCustomTransport:true,
  diagnosticsHooks:{log:e=>events.push(e),trace:e=>events.push(e),metric:e=>events.push(e)},
  fetcher:async()=>new Response(JSON.stringify({error:secret,correlationId:secret,detail:id+"/"+secret,[secret]:id}),{status:403,headers:{"Content-Type":"application/json","X-Correlation-Id":secret}})});
 try{await c.useAgentKey(id+":"+secret);assert.fail();}
 catch(e){assert.ok(e instanceof AegirSecurityError);const visible=JSON.stringify({error:e,message:e.message,events});assert.ok(!visible.includes(id));assert.ok(!visible.includes(secret));assert.equal(e.correlationId,null);}
 finally{c.close();}
});
