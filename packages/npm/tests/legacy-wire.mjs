// Foxlin Industries. Genuine ephemeral loopback TLS, never a mock positive Aegir authority.
import assert from "node:assert/strict";
import https from "node:https";
import {AegirSecurityClient,AegirSecurityError} from "../dist/esm/index.js";
const base=process.env.AEGIR_LEGACY_BASE,pin=process.env.AEGIR_LEGACY_PIN;
assert.ok(base?.startsWith("https://127.0.0.1:"));
const trustedBase=base.replace("127.0.0.1","localhost");let passed=0;
const make=(extra={})=>new AegirSecurityClient({baseUrl:trustedBase,certificateSha256:pin,developerKey:"synthetic-wire-credential",timeoutMs:2000,...extra});
const control=()=>new Promise((resolve,reject)=>https.get(trustedBase.replace("/apis","/control"),r=>{let t="";r.on("data",c=>t+=c);r.on("end",()=>resolve(JSON.parse(t)));}).on("error",reject));
async function test(name,run){await run();passed++;console.log("ok - legacy wire "+name);}
if(process.env.AEGIR_LEGACY_UNTRUSTED_ONLY==="true"){
 await assert.rejects(()=>new AegirSecurityClient({baseUrl:trustedBase,developerKey:"synthetic-wire-credential",timeoutMs:2000}).introspectToken("ok"),AegirSecurityError);
 console.log(JSON.stringify({language:"node",cases:1,untrustedCaDenied:true}));
}else{
 await test("valid exact loopback pin",async()=>assert.equal((await make().introspectToken("ok")).active,true));
 await test("normal TLS chain and hostname",async()=>assert.equal((await make({baseUrl:trustedBase,certificateSha256:undefined}).introspectToken("ok")).active,true));
 for(const [name,options] of [["wrong pin",{certificateSha256:"0".repeat(64)}],["hostname mismatch",{baseUrl:base,certificateSha256:undefined}],
   ["matching pin wrong hostname",{baseUrl:base}],["matching pin expired certificate",{baseUrl:process.env.AEGIR_LEGACY_EXPIRED_BASE,certificateSha256:process.env.AEGIR_LEGACY_EXPIRED_PIN}]])await test(name+" sends no credential HTTP",async()=>{const before=await control();await assert.rejects(()=>make(options).introspectToken("ok"),AegirSecurityError);const after=await control();assert.equal(after.requests,before.requests);});
 for(const mode of ["duplicate","wrongmime","jsonp","badutf8","deep","collection","oversize","expired","illtyped"])
 await test(mode+" fail closed",async()=>await assert.rejects(()=>make().introspectToken(mode),AegirSecurityError));
 await test("redirect does not reach sink",async()=>{await assert.rejects(()=>make().introspectToken("redirect"),AegirSecurityError);assert.equal((await control()).sink,0);});
 await test("proxy environment not consulted",async()=>{const old=process.env.HTTPS_PROXY;process.env.HTTPS_PROXY="http://127.0.0.1:1";try{assert.equal((await make().introspectToken("ok")).active,true);}finally{if(old===undefined)delete process.env.HTTPS_PROXY;else process.env.HTTPS_PROXY=old;}});
 await test("bounded slow body timeout",async()=>{const start=Date.now();await assert.rejects(()=>make({timeoutMs:50}).introspectToken("slow"),AegirSecurityError);assert.ok(Date.now()-start<700);});
 await test("close aborts owned request",async()=>{const c=make();const pending=c.introspectToken("slow");setTimeout(()=>c.close(),30);await assert.rejects(()=>pending,AegirSecurityError);await assert.rejects(()=>c.introspectToken("ok"),AegirSecurityError);});
 console.log(JSON.stringify({language:"node",cases:passed,syntheticTlsOnly:true,redirectSinkRequests:(await control()).sink}));
}
