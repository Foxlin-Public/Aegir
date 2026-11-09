"""Foxlin Industries. Retained SDK adversarial cases, not mock authority certification."""
import json,pickle,threading,time,unittest
from foxlin_aegir_security import AegirSecurityClient,AegirSecurityError
from foxlin_aegir_security._legacy import strict_json,LegacyFailure
BASE="https://example.invalid/apis"
TOKEN=dict(access_token="opaque.synthetic.token",token_type="Bearer",expires_in=1800,expires_at="2099-01-01T00:00:00Z",scope="security:read",scopes=["security:read"],tenant_id="tenant_test",subject="subject_test")
def client(value,status=200,**options):
 return AegirSecurityClient(base_url=BASE,allow_trusted_custom_transport=True,transport=lambda *a:(status,value),**options)
class LegacyTests(unittest.TestCase):
 def test_unsafe_origins_reject_before_credentials(self):
  for url in ("http://example.invalid/apis","https://u:p@example.invalid/apis","https://example.invalid/a?q=1","https://example.invalid/#f","https://example.invalid/a/../apis"):
   with self.assertRaises(ValueError):AegirSecurityClient(base_url=url,developer_key="synthetic-private")
 def test_adapter_needs_explicit_trust(self):
  with self.assertRaises(ValueError):AegirSecurityClient(base_url=BASE,transport=lambda *a:(200,{}))
 def test_duplicate_escaped_keys_reject(self):
  for source in ('{"valid":false,"valid":true}','{"valid":false,"\\u0076alid":true}'):
   with self.assertRaises(LegacyFailure):strict_json(source)
 def test_deep_collections_and_nonfinite_reject(self):
  for source in ('{"n":'*40+'1'+'}'*40,json.dumps([0]*4097),'NaN','{"a":Infinity}'):
   with self.assertRaises(LegacyFailure):strict_json(source)
 def test_oversized_response_rejects(self):
  with self.assertRaises(AegirSecurityError):client(dict(valid=True,status="Valid",detail=None,n="x"*1048577)).verifyTransactionReceipt({})
 def test_contradictory_and_illtyped_permit_reject(self):
  for v in (dict(valid=True,status="SignatureInvalid",detail=None),dict(valid=1,status="Valid",detail=None),dict(valid=True,status="future",detail=None)):
   with self.assertRaises(AegirSecurityError):client(v).verifyTransactionReceipt({})
 def test_negative_verification_remains_data(self):
  v=dict(valid=False,status="SignatureInvalid",detail=None);self.assertEqual(v,client(v).verifyTransactionReceipt({}))
 def test_optional_outer_extension_is_compatible(self):
  self.assertTrue(client(dict(valid=True,status="Valid",detail=None,optional="compatible")).verifyTransactionReceipt({})["valid"])
 def test_exact_status_enforced(self):
  with self.assertRaises(AegirSecurityError):client(dict(valid=True,status="Valid",detail=None),status=201).verifyTransactionReceipt({})
 def test_invalid_active_introspection_rejects(self):
  for v in ({"active":"yes"},{"active":True},{"active":False,"sub":"test"}):
   with self.assertRaises(AegirSecurityError):client(v).introspectToken("synthetic-target")
 def test_expired_and_wrong_tenant_introspection_reject(self):
  v=dict(active=True,sub="subject_test",tenant_id="tenant_test",exp=1,scopes=[],roles=[])
  with self.assertRaises(AegirSecurityError):client(v).introspectToken("target")
  with self.assertRaises(AegirSecurityError):client(v|dict(exp=4070908800),expected_tenant_id="other").introspectToken("target")
 def test_token_expiry_scope_subject_type_reject(self):
  for patch in (dict(expires_at="2000-01-01T00:00:00Z"),dict(scope="admin:full",scopes=["admin:full"]),dict(subject=None),dict(token_type="Basic")):
   with self.assertRaises(AegirSecurityError):client(TOKEN|patch).useNarrowedToken("security:read")
 def test_valid_opaque_token_still_usable(self):
  self.assertEqual(TOKEN,client(TOKEN).useNarrowedToken("security:read"))
 def test_agent_subject_binding_rejects(self):
  with self.assertRaises(AegirSecurityError):client(TOKEN).useAgentKey("other:synthetic")
 def test_transaction_and_subject_binding_reject(self):
  v=dict(transactionId="other",tenantId="tenant_test",callerPrincipalType="Agent",callerPrincipalId="a",declaredAction="x",authorizationDecision="Pending",status="Created")
  with self.assertRaises(AegirSecurityError):client(v).getTransaction("expected")
  with self.assertRaises(AegirSecurityError):client(dict(subjectId="other",graph={},exposure={})).scanIdentity("expected")
 def test_client_repr_and_pickle_cannot_leak(self):
  c=AegirSecurityClient(base_url=BASE,developer_key="synthetic-private-sentinel")
  self.assertNotIn("synthetic-private-sentinel",repr(c))
  with self.assertRaises(TypeError):pickle.dumps(c)
  with self.assertRaises(TypeError):vars(c)
 def test_transport_exception_sanitized(self):
  def bad(*a):raise RuntimeError("synthetic-private-sentinel")
  c=AegirSecurityClient(base_url=BASE,allow_trusted_custom_transport=True,transport=bad)
  with self.assertRaises(AegirSecurityError) as caught:c.introspectToken("target")
  self.assertNotIn("synthetic-private-sentinel",str(caught.exception))
 def test_error_body_secret_echo_sanitized(self):
  c=client(dict(error="forbidden",message="synthetic-private-sentinel",agentKey="different-secret"),status=403,developer_key="synthetic-private-sentinel")
  with self.assertRaises(AegirSecurityError) as caught:c.introspectToken("target")
  self.assertEqual("forbidden",caught.exception.code)
  self.assertNotIn("synthetic-private-sentinel",json.dumps(caught.exception.body));self.assertNotIn("different-secret",json.dumps(caught.exception.body))
 def test_precancelled_never_invokes_adapter(self):
  cancel=threading.Event();cancel.set();calls=[]
  c=AegirSecurityClient(base_url=BASE,cancel_event=cancel,allow_trusted_custom_transport=True,transport=lambda *a:(calls.append(1) or (200,{})))
  with self.assertRaises(AegirSecurityError):c.introspectToken("target")
  self.assertEqual([],calls)
 def test_timeout_and_close_prevent_late_token_adoption(self):
  def slow(*a):time.sleep(.08);return 200,TOKEN
  c=AegirSecurityClient(base_url=BASE,timeout_seconds=.02,allow_trusted_custom_transport=True,transport=slow)
  start=time.monotonic()
  with self.assertRaises(AegirSecurityError):c.useNarrowedToken("security:read")
  self.assertLess(time.monotonic()-start,.5);c.close();time.sleep(.1);self.assertIsNone(c._access_token)
  with self.assertRaises(AegirSecurityError):c.getToken()

 def test_numeric_identity_enum_and_public_model_accept_actual_wire(self):
  import test_client as fixtures
  from foxlin_aegir_security.models import IdentityGraphNode
  graph=fixtures.AegirSecurityClientTests()._graph_payload();graph["nodes"][0]["nodeType"]=6
  self.assertEqual("User",client(graph).getIdentityGraph("developer:dev_123").nodes[0].nodeType)
  self.assertEqual("User",IdentityGraphNode.from_json(graph["nodes"][0]|dict(nodeType=6)).nodeType)
  with self.assertRaises(ValueError):IdentityGraphNode.from_json(graph["nodes"][0]|dict(nodeType=True))
  graph["nodes"][0]["nodeType"]=99
  with self.assertRaises(AegirSecurityError):client(graph).getIdentityGraph("developer:dev_123")
 def test_named_action_uses_canonical_numeric_wire(self):
  import test_client as fixtures
  from foxlin_aegir_security import PerformIdentityActionRequest,IdentityActionType
  captured=[]
  def adapter(u,m,h,b):
   captured.append(json.loads(b));return 200,fixtures.AegirSecurityClientTests()._action_payload()|dict(actionType=3,status=1)
  c=AegirSecurityClient(base_url=BASE,allow_trusted_custom_transport=True,transport=adapter)
  result=c.performAction(PerformIdentityActionRequest(subjectId="developer:dev_123",actionType=IdentityActionType.VerifyConnection))
  self.assertEqual(3,captured[0]["actionType"]);self.assertEqual("VerifyConnection",result.actionType);self.assertEqual("Completed",result.status)

 def test_malformed_score_rejects_without_credential_echo(self):
  import test_client as fixtures
  graph=fixtures.AegirSecurityClientTests()._graph_payload();graph["scores"]["exposureScore"]="synthetic-private-sentinel"
  with self.assertRaises(AegirSecurityError) as caught:client(graph,developer_key="synthetic-private-sentinel").getIdentityGraph("developer:dev_123")
  self.assertNotIn("synthetic-private-sentinel",str(caught.exception))

 def test_raw_canonical_developer_user_graph_ids_and_numeric_enums(self):
  import test_client as fixtures
  for kind,number,name in (("developer",2,"Developer"),("user",6,"User")):
   graph=fixtures.AegirSecurityClientTests()._graph_payload();graph["graphId"]="graph:"+kind+":raw_subject";graph["nodes"][0]["nodeType"]=number
   self.assertEqual(name,client(graph).getIdentityGraph("raw_subject").nodes[0].nodeType)

 def test_exposure_graph_binding_without_invented_subject_field(self):
  import test_client as fixtures
  graph=fixtures.AegirSecurityClientTests()._graph_payload();graph["graphId"]="graph:developer:raw_subject"
  exposure=fixtures.AegirSecurityClientTests()._exposure_payload();exposure["graphId"]=graph["graphId"]
  self.assertEqual(graph["graphId"],client(exposure).getExposureSummary("raw_subject").graphId)
  scan=dict(subjectId="raw_subject",graph=graph,exposure=exposure,actionHistory=[])
  self.assertEqual(graph["graphId"],client(scan).scanIdentity("raw_subject").graph.graphId)

 def test_raw_subject_rejects_unrelated_and_mismatched_nested_graphs(self):
  import test_client as fixtures
  graph=fixtures.AegirSecurityClientTests()._graph_payload();graph["graphId"]="graph:developer:other_subject"
  with self.assertRaises(AegirSecurityError):client(graph).getIdentityGraph("raw_subject")
  exposure=fixtures.AegirSecurityClientTests()._exposure_payload();exposure["graphId"]=graph["graphId"]
  with self.assertRaises(AegirSecurityError):client(exposure).getExposureSummary("raw_subject")
  graph["graphId"]="graph:developer:raw_subject";exposure["graphId"]="graph:user:raw_subject"
  with self.assertRaises(AegirSecurityError):client(dict(subjectId="raw_subject",graph=graph,exposure=exposure,actionHistory=[])).scanIdentity("raw_subject")

 def test_diagnostic_worker_shares_deadline_without_late_token_adoption(self):
  from foxlin_aegir_security import AegirDiagnosticsHooks
  release=threading.Event();calls=[]
  hooks=AegirDiagnosticsHooks(trace=lambda _:release.wait(2))
  c=AegirSecurityClient(base_url=BASE,timeout_seconds=.03,access_token="old-synthetic-token",diagnostics_hooks=hooks,
   allow_trusted_custom_transport=True,transport=lambda *a:(calls.append(a) or (200,[])))
  started=time.monotonic()
  try:
   with self.assertRaises(AegirSecurityError):c.useNarrowedToken("security:read")
   self.assertLess(time.monotonic()-started,.5);self.assertEqual([],calls);self.assertEqual("old-synthetic-token",c._access_token)
  finally:release.set();hooks.trace=None
  time.sleep(.01);self.assertEqual([],calls);c.listProviders();self.assertEqual("Bearer old-synthetic-token",calls[0][2]["Authorization"]);c.close()

 def test_cancel_and_close_interrupt_diagnostic_worker_before_request(self):
  from foxlin_aegir_security import AegirDiagnosticsHooks
  for mode in ("cancel","close"):
   release=threading.Event();calls=[]
   c=AegirSecurityClient(base_url=BASE,timeout_seconds=1,diagnostics_hooks=AegirDiagnosticsHooks(trace=lambda _:release.wait(2)),
    allow_trusted_custom_transport=True,transport=lambda *a:(calls.append(a) or (200,TOKEN)))
   timer=threading.Timer(.02,c.close if mode=="close" else c.cancel_pending);timer.start()
   try:
    with self.assertRaises(AegirSecurityError):c.useNarrowedToken("security:read")
    self.assertEqual([],calls);self.assertIsNone(c._access_token)
   finally:release.set();timer.join();c.close()
   time.sleep(.01);self.assertEqual([],calls)

 def test_diagnostic_exceptions_are_best_effort_and_do_not_escape(self):
  from foxlin_aegir_security import AegirDiagnosticsHooks
  def fail(_):raise RuntimeError("synthetic-private-diagnostic")
  c=client([],diagnostics_hooks=AegirDiagnosticsHooks(trace=fail,log=fail,metric=fail))
  self.assertEqual([],c.listProviders());c.close()

 def test_configured_credential_components_cannot_reflect_into_errors_or_diagnostics(self):
  from foxlin_aegir_security import AegirDiagnosticsHooks
  principal="synthetic_component_id";secret="private_component_marker"
  for field in ("developer_key","access_token","config_key"):
   for reflected in (principal,secret):
    events=[];hooks=AegirDiagnosticsHooks(log=events.append,trace=events.append,metric=events.append)
    c=client(dict(error=reflected,correlationId=reflected,detail="prefix-"+reflected+"-suffix")|{reflected:"value"},status=403,diagnostics_hooks=hooks,**{field:principal+":"+secret})
    try:
     with self.assertRaises(AegirSecurityError) as caught:c.introspectToken("synthetic-target")
     visible=json.dumps(dict(error=vars(caught.exception),message=str(caught.exception),events=events))
     self.assertNotIn(principal,visible);self.assertNotIn(secret,visible);self.assertIsNone(caught.exception.correlationId)
    finally:c.close()

 def test_agent_credential_secret_half_cannot_become_error_metadata(self):
  from foxlin_aegir_security import AegirDiagnosticsHooks
  principal="synthetic_agent_component";secret="private_agent_component";events=[]
  c=client(dict(error=secret,correlationId=secret,detail=principal+"/"+secret)|{secret:principal},status=403,
   diagnostics_hooks=AegirDiagnosticsHooks(log=events.append,trace=events.append,metric=events.append))
  try:
   with self.assertRaises(AegirSecurityError) as caught:c.useAgentKey(principal+":"+secret)
   visible=json.dumps(dict(error=vars(caught.exception),message=str(caught.exception),events=events))
   self.assertNotIn(principal,visible);self.assertNotIn(secret,visible);self.assertIsNone(caught.exception.correlationId)
   self.assertIsNone(c._access_token)
  finally:c.close()
