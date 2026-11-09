"""Foxlin Industries. Genuine ephemeral loopback TLS; not real Aegir authority acceptance."""
import os,json,http.client,threading,time
from urllib.parse import urlsplit
from foxlin_aegir_security import AegirSecurityClient,AegirSecurityError
if os.environ.get("AEGIR_LEGACY_TRACE")=="true":
 import sys
 def trace(frame,event,arg):
  if event=="exception" and frame.f_code.co_filename.endswith("_legacy.py"):
   print(json.dumps(dict(traceException=type(arg[1]).__name__,line=frame.f_lineno,verifyCode=getattr(arg[1],"verify_code",None))),file=sys.stderr)
  return trace
 sys.settrace(trace)
base=os.environ["AEGIR_LEGACY_BASE"];pin=os.environ["AEGIR_LEGACY_PIN"];trusted=base.replace("127.0.0.1","localhost");passed=0
assert base.startswith("https://127.0.0.1:")
def client(**options):
 args=dict(base_url=trusted,certificate_sha256=pin,developer_key="synthetic-wire-credential",timeout_seconds=2);args.update(options);return AegirSecurityClient(**args)
def control():
 u=urlsplit(trusted);c=http.client.HTTPSConnection(u.hostname,u.port,timeout=2)
 try:c.request("GET","/control");return json.loads(c.getresponse().read())
 finally:c.close()
def rejects(action):
 try:action()
 except AegirSecurityError:return
 raise AssertionError("Unsafe response or transport accepted")
def test(name,action):
 global passed
 action();passed+=1;print("ok - legacy wire "+name)
if os.environ.get("AEGIR_LEGACY_UNTRUSTED_ONLY")=="true":
 rejects(lambda:client(base_url=trusted,certificate_sha256=None).introspectToken("ok"));print(json.dumps(dict(language="python",cases=1,untrustedCaDenied=True)))
else:
 def authorized(**options):assert client(**options).introspectToken("ok")["active"] is True
 test("valid exact loopback pin",authorized)
 test("normal TLS chain and hostname",lambda:authorized(base_url=trusted,certificate_sha256=None))
 def no_http(options):
  before=control();rejects(lambda:client(**options).introspectToken("ok"));assert control()["requests"]==before["requests"]
 test("wrong pin sends no credential HTTP",lambda:no_http(dict(certificate_sha256="0"*64)))
 test("hostname mismatch sends no credential HTTP",lambda:no_http(dict(base_url=base,certificate_sha256=None)))
 test("matching pin wrong hostname sends no credential HTTP",lambda:no_http(dict(base_url=base)))
 test("matching pin expired certificate sends no credential HTTP",lambda:no_http(dict(base_url=os.environ["AEGIR_LEGACY_EXPIRED_BASE"],certificate_sha256=os.environ["AEGIR_LEGACY_EXPIRED_PIN"])))
 for mode in ["duplicate","wrongmime","jsonp","badutf8","deep","collection","oversize","expired","illtyped"]:
  test(mode+" fail closed",lambda m=mode:rejects(lambda:client().introspectToken(m)))
 def redirect():rejects(lambda:client().introspectToken("redirect"));assert control()["sink"]==0
 test("redirect does not reach sink",redirect)
 def proxy():
  old=os.environ.get("HTTPS_PROXY");os.environ["HTTPS_PROXY"]="http://127.0.0.1:1"
  try:authorized()
  finally:
   if old is None:os.environ.pop("HTTPS_PROXY",None)
   else:os.environ["HTTPS_PROXY"]=old
 test("proxy environment not consulted",proxy)
 def timeout():
  start=time.monotonic();rejects(lambda:client(timeout_seconds=.05).introspectToken("slow"));assert time.monotonic()-start<.7
 test("bounded slow body timeout",timeout)
 def close():
  c=client();timer=threading.Timer(.03,c.close);timer.start()
  try:rejects(lambda:c.introspectToken("slow"));rejects(lambda:c.introspectToken("ok"))
  finally:timer.join()
 test("close aborts owned request",close)
 print(json.dumps(dict(language="python",cases=passed,syntheticTlsOnly=True,redirectSinkRequests=control()["sink"])))
