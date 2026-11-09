// Copyright Foxlin Industries. Validates the actual retained wire DTOs before model conversion.
package cloud.foxlin.aegir.security;
import java.util.*;import java.time.OffsetDateTime;
final class LegacyContracts{
 private static final Map<String,List<String>>ENUMS=Map.ofEntries(Map.entry("IdentityActionType",List.of("LockIdentity","DisconnectService","VerifyConnection","RequestClarity")),Map.entry("IdentityActionStatus",List.of("Completed","Reversed")),Map.entry("IdentityGraphNodeType",List.of("Platform","Developer","DeveloperKey","Application","Environment","User","Device","Credential","Challenge","Token","AuditAnchor","PolicyScope","ExternalService")),Map.entry("IdentityGraphEdgeType",List.of("Owns","Issued","Registered","BelongsTo","AuthorizedFor","ScopedTo","Uses","PresentedBy","DerivedFrom","ApprovedBy","RevokedBy","AnchoredBy","ConnectedTo","ObservedOn")),Map.entry("ExposureFindingCategory",List.of("WeakConnection","UnknownConnection","StaleCredential","HighRiskLinkage")),Map.entry("ExposureFindingSeverity",List.of("Low","Medium","High")));
 private static final Map<String,String>SCHEMAS=Map.ofEntries(
 Map.entry("IdentityGraphScores","exposureScore:number trustScore:number connectionClarityScore:number"),
 Map.entry("IdentityGraphNode","nodeId:string nodeType:IdentityGraphNodeType displayName:string status:string trustTier:string observedAtUtc:string lastVerifiedAtUtc:*string metadata:metadata"),
 Map.entry("IdentityGraphEdge","edgeId:string edgeType:IdentityGraphEdgeType fromNodeId:string toNodeId:string status:string trustWeight:number evidenceType:string reason:string observedAtUtc:string lastVerifiedAtUtc:*string metadata:metadata"),
 Map.entry("IdentityGraphSnapshot","graphId:string generatedAtUtc:string scores:IdentityGraphScores nodes:[]IdentityGraphNode edges:[]IdentityGraphEdge metadata:metadata"),
 Map.entry("ExposureFinding","findingId:string category:ExposureFindingCategory severity:ExposureFindingSeverity summary:string nodeId:*string edgeId:*string metadata:metadata"),
 Map.entry("ExposureSummary","graphId:string generatedAtUtc:string exposureScore:number findings:[]ExposureFinding summaryText:string"),
 Map.entry("IdentityActionRecord","actionId:string subjectId:string actionType:IdentityActionType status:IdentityActionStatus targetNodeId:*string reason:*string requestedAtUtc:string reversedAtUtc:*string reverseReason:*string metadata:metadata"),
 Map.entry("ScanIdentityResult","subjectId:string graph:IdentityGraphSnapshot exposure:ExposureSummary actionHistory:[]IdentityActionRecord"));
 static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid or mismatched Aegir response contract.");}
 static boolean input(String s,int limit,boolean empty){return s!=null&&(empty||!s.trim().isEmpty())&&s.length()<=limit&&s.indexOf(0)<0&&s.indexOf('\r')<0&&s.indexOf('\n')<0;}
 static void shape(Object value,String type){
  if(type.startsWith("*")){if(value==null)return;shape(value,type.substring(1));return;}
  if(type.startsWith("[]")){List<Object>a=IntegrationJson.array(value);if(a.size()>10000)throw invalid();for(Object x:a)shape(x,type.substring(2));return;}
  if(type.equals("metadata")){Map<String,Object>m=IntegrationJson.object(value);if(m.size()>1000)throw invalid();for(Map.Entry<String,Object>e:m.entrySet()){if(!input(e.getKey(),512,false))throw invalid();shape(e.getValue(),"*string");}return;}
  if(type.equals("number")){if(!(value instanceof Number))throw invalid();return;}
  if(type.equals("string")){if(!(value instanceof String)||!input((String)value,16384,true))throw invalid();return;}
  String schema=SCHEMAS.get(type);if(schema!=null){Map<String,Object>m=IntegrationJson.object(value);String[]fields=schema.split(" ");if(m.size()<fields.length)throw invalid();for(String f:fields){String[]pair=f.split(":",2);if(!m.containsKey(pair[0]))throw invalid();Object v=enumName(m.get(pair[0]),pair[1]);m.put(pair[0],v);shape(v,pair[1]);if(pair[0].endsWith("Id")&&v!=null&&(!(v instanceof String)||!input((String)v,512,false)))throw invalid();if(pair[0].endsWith("AtUtc")&&v!=null){try{OffsetDateTime.parse((String)v);}catch(Exception e){throw invalid();}}}return;}
  if(!(value instanceof String))throw invalid();String s=(String)value;try{switch(type){case "IdentityActionType":SecurityModels.IdentityActionType.valueOf(s);break;case "IdentityActionStatus":SecurityModels.IdentityActionStatus.valueOf(s);break;case "IdentityGraphNodeType":SecurityModels.IdentityGraphNodeType.valueOf(s);break;case "IdentityGraphEdgeType":SecurityModels.IdentityGraphEdgeType.valueOf(s);break;case "ExposureFindingCategory":SecurityModels.ExposureFindingCategory.valueOf(s);break;case "ExposureFindingSeverity":SecurityModels.ExposureFindingSeverity.valueOf(s);break;default:throw invalid();}}catch(Exception e){throw invalid();}
 }
 static Object enumName(Object value,String type){List<String>names=ENUMS.get(type);if(names==null)return value;if(value instanceof Long){long n=(Long)value;if(n<1||n>names.size())throw invalid();return names.get((int)n-1);}if(!(value instanceof String)||!names.contains((String)value))throw invalid();return value;}
 static long actionNumber(Object value){List<String>names=ENUMS.get("IdentityActionType");int index=names.indexOf(value);if(index<0)throw invalid();return index+1;}
 static boolean graphBinding(Object id,String subject){return input(subject,512,false)&&("graph:"+subject).equals(id)||input(subject,512,false)&&(("graph:developer:"+subject).equals(id)||("graph:user:"+subject).equals(id));}
 static void graph(Map<String,Object>m,String subject){shape(m,"IdentityGraphSnapshot");if(!graphBinding(m.get("graphId"),subject))throw invalid();}
 static void exposure(Map<String,Object>m,String subject){shape(m,"ExposureSummary");if(!graphBinding(m.get("graphId"),subject))throw invalid();}
 static void action(Map<String,Object>m,String subject,String id){shape(m,"IdentityActionRecord");if(subject!=null&&!subject.equals(m.get("subjectId"))||id!=null&&!id.equals(m.get("actionId")))throw invalid();}
 static void scan(Map<String,Object>m,String subject){shape(m,"ScanIdentityResult");if(!subject.equals(m.get("subjectId")))throw invalid();graph(IntegrationJson.object(m.get("graph")),subject);exposure(IntegrationJson.object(m.get("exposure")),subject);for(Object a:IntegrationJson.array(m.get("actionHistory")))action(IntegrationJson.object(a),subject,null);}
}
