// Copyright Foxlin Industries. Bounded UTF-8 newline JSON-RPC subset for the local stdio process.
export const MAX_INPUT = 65536;
export const MAX_OUTPUT = 262144;
export function protocolError(code) { return Object.assign(new Error("Invalid MCP protocol message."),{code}); }

export function parseFrame(bytes) {
  if (bytes.length > MAX_INPUT) throw protocolError(-32600);
  let text,value;
  try { text = new TextDecoder("utf-8",{fatal:true}).decode(bytes); value=JSON.parse(text); }
  catch { throw protocolError(-32700); }
  // JSON.parse accepts duplicate keys. Inspect parsed-valid lexical strings without evaluating them.
  const stack=[];
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(c==="{")stack.push(new Set()); else if(c==="[")stack.push(null);
    else if(c==="}"||c==="]")stack.pop();
    else if(c==='"') {
      let end=i+1;for(;end<text.length;end++){if(text[end]==="\\"){end++;continue;}if(text[end]==='"')break;}
      let next=end+1;while(/\s/.test(text[next]??"") && next<text.length)next++;
      if(text[next]===":" && stack.at(-1) instanceof Set) {
        const key=JSON.parse(text.slice(i,end+1)),keys=stack.at(-1);
        if(keys.has(key))throw protocolError(-32600);keys.add(key);
      }
      i=end;
    }
    if(stack.length>16)throw protocolError(-32600);
  }
  const check=(v,depth=0)=>{
    if(depth>16)throw protocolError(-32600);
    if(v && typeof v==="object") {
      if(Object.keys(v).length>128)throw protocolError(-32600);
      for(const x of Object.values(v))check(x,depth+1);
    }
  };check(value);
  if(!value || Array.isArray(value) || typeof value!=="object" || value.jsonrpc!=="2.0" ||
      typeof value.method!=="string" || value.method.length>128 ||
      Object.keys(value).some(k=>!["jsonrpc","id","method","params"].includes(k)) ||
      (value.params!==undefined && (!value.params || Array.isArray(value.params) || typeof value.params!=="object"))) throw protocolError(-32600);
  if("id"in value && !(typeof value.id==="string" && value.id.length>0 && value.id.length<=128 || Number.isSafeInteger(value.id)))throw protocolError(-32600);
  return value;
}

export async function* readFrames(input) {
  let pending=Buffer.alloc(0),discard=false;
  for await(const chunk of input) {
    let bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);
    while(bytes.length) {
      const newline=bytes.indexOf(10),piece=newline<0?bytes:bytes.subarray(0,newline);
      if(!discard && pending.length+piece.length>MAX_INPUT){pending=Buffer.alloc(0);discard=true;yield {error:protocolError(-32600)};}
      if(!discard)pending=Buffer.concat([pending,piece]);
      if(newline<0)break;
      if(!discard){try{yield {message:parseFrame(pending)};}catch(error){yield {error};}}
      pending=Buffer.alloc(0);discard=false;bytes=bytes.subarray(newline+1);
    }
  }
  if(pending.length || discard)yield {error:protocolError(-32700)};
}
