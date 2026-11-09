package cloud.foxlin.aegir.security;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class AegirSecurityClient implements AutoCloseable
{
    private final String baseUrl;
    private final String developerKey;
    private volatile HttpClient httpClient;
    private final java.util.concurrent.ExecutorService executor;
    private final java.util.Set<java.util.concurrent.CompletableFuture<?>> pending = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final java.time.Duration timeout;
    private final java.util.Set<java.util.concurrent.Future<?>> pendingDiagnostics=java.util.concurrent.ConcurrentHashMap.newKeySet();
    // Uncooperative host callbacks cannot be killed. No queue and four global
    // daemon workers bound stranded callbacks across every client instance.
    private static final java.util.concurrent.ThreadPoolExecutor DIAGNOSTICS=new java.util.concurrent.ThreadPoolExecutor(0,4,1,java.util.concurrent.TimeUnit.SECONDS,new java.util.concurrent.SynchronousQueue<>(),r->{Thread t=new Thread(r,"aegir-security-diagnostics");t.setDaemon(true);return t;},new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());
    private volatile boolean closed;
    private final AegirDiagnosticsHooks diagnosticsHooks;

    public AegirSecurityClient(String baseUrl, String configKey, String developerKey)
    {
        this(baseUrl, configKey, developerKey, null, null);
    }

    public AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient httpClient)
    {
        this(baseUrl, configKey, developerKey, httpClient, null);
    }

    public AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient httpClient, AegirDiagnosticsHooks diagnosticsHooks)
    {
        this(baseUrl, configKey, developerKey, httpClient, diagnosticsHooks, false, null, java.time.Duration.ofSeconds(15));
    }

    /** An opaque custom HttpClient is trusted host code; its wire behavior cannot be certified. */
    public AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient client, AegirDiagnosticsHooks hooks, boolean trustHttpAdapter) {
        this(baseUrl, configKey, developerKey, client, hooks, trustHttpAdapter, null, java.time.Duration.ofSeconds(15));
    }
    /** Explicit local development factory, exact DER SHA256 and HTTPS loopback only. */
    public static AegirSecurityClient pinnedLoopbackDevelopment(String baseUrl, String developerKey, String certificateSha256, java.time.Duration timeout, AegirDiagnosticsHooks hooks) {
        return new AegirSecurityClient(baseUrl, null, developerKey, null, hooks, false, certificateSha256, timeout);
    }
    private AegirSecurityClient(String baseUrl, String ignoredConfigKey, String developerKey, HttpClient supplied, AegirDiagnosticsHooks hooks, boolean trustAdapter, String pin, java.time.Duration timeout) {
        URI uri;
        try { uri=URI.create(baseUrl); } catch(Exception failure) { throw new IllegalArgumentException("Clean HTTPS base required."); }
        if(!"https".equals(uri.getScheme())||uri.getHost()==null||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||uri.getRawPath().contains("%")||uri.getPath().contains("..")||timeout==null||timeout.toMillis()<1||timeout.compareTo(java.time.Duration.ofSeconds(30))>0)throw new IllegalArgumentException("Clean HTTPS base and bounded timeout required.");
        if(developerKey!=null&&!LegacyContracts.input(developerKey,2048,true))throw new IllegalArgumentException("Invalid credential.");
        if(pin!=null&&(!pin.matches("[a-fA-F0-9]{64}")||!("localhost".equals(uri.getHost())||"127.0.0.1".equals(uri.getHost())||"[::1]".equals(uri.getHost()))))throw new IllegalArgumentException("Exact loopback development pin required.");
        boolean concrete=supplied==null||"java.net.http".equals(supplied.getClass().getModule().getName());
        if(!concrete&&!trustAdapter)throw new IllegalArgumentException("Opaque HttpClient requires explicit host trust.");
        this.baseUrl=baseUrl.replaceAll("/+$", "");this.developerKey=developerKey;this.diagnosticsHooks=hooks;this.timeout=timeout;
        executor=java.util.concurrent.Executors.newFixedThreadPool(2,r->{Thread t=new Thread(r,"aegir-security-transport");t.setDaemon(true);return t;});
        try {this.httpClient=concrete?LegacyTransport.create(executor,timeout,pin):supplied;}
        catch(Exception failure){executor.shutdownNow();throw new IllegalArgumentException("TLS transport unavailable.");}
    }
    @Override public String toString(){return "AegirSecurityClient(<redacted>)";}
    @Override public void close(){closed=true;for(java.util.concurrent.CompletableFuture<?> task:pending)task.cancel(true);for(java.util.concurrent.Future<?> task:pendingDiagnostics)task.cancel(true);executor.shutdownNow();httpClient=null;}

    private final class RequestLifetime {
        final long deadline=System.nanoTime()+timeout.toNanos();
        void check()throws IOException,InterruptedException{if(Thread.currentThread().isInterrupted())throw new InterruptedException("Aegir operation canceled.");if(closed)throw new IOException("Aegir client closed.");if(deadline-System.nanoTime()<=0)throw new IOException("Aegir operation timed out.");}
        long remaining()throws IOException,InterruptedException{check();return Math.max(1,deadline-System.nanoTime());}
    }
    public SecurityModels.ScanIdentityResult scanIdentity(String subjectId)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();Map<String,Object>payload=asMap(request(life,"scanIdentity","/security/scan/"+encode(subjectId),"GET",null));LegacyContracts.scan(payload,subjectId);SecurityModels.ScanIdentityResult result=toScanIdentityResult(payload);life.check();return result;
    }
    public SecurityModels.IdentityGraphSnapshot getIdentityGraph(String subjectId)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();Map<String,Object>payload=asMap(request(life,"getIdentityGraph","/security/graphs/"+encode(subjectId),"GET",null));LegacyContracts.graph(payload,subjectId);SecurityModels.IdentityGraphSnapshot result=new SecurityModels.IdentityGraphSnapshot(payload);life.check();return result;
    }
    public String getIdentityGraphJson(String subjectId)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();Map<String,Object>payload=asMap(request(life,"getIdentityGraph","/security/graphs/"+encode(subjectId),"GET",null));LegacyContracts.graph(payload,subjectId);String result=JsonSupport.stringify(payload);life.check();return result;
    }
    public SecurityModels.ExposureSummary getExposureSummary(String subjectId)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();Map<String,Object>payload=asMap(request(life,"getExposureSummary","/security/exposure/"+encode(subjectId),"GET",null));LegacyContracts.exposure(payload,subjectId);SecurityModels.ExposureSummary result=new SecurityModels.ExposureSummary(payload);life.check();return result;
    }
    public SecurityModels.IdentityActionRecord performAction(PerformIdentityActionRequest action)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();Map<String,Object>payload=asMap(request(life,"performAction","/security/actions","POST",action.toMap()));LegacyContracts.action(payload,action.getSubjectId(),null);if(!action.getActionType().equals(payload.get("actionType"))||!"Completed".equals(payload.get("status"))||!java.util.Objects.equals(action.getTargetNodeId(),payload.get("targetNodeId")))throw LegacyContracts.invalid();SecurityModels.IdentityActionRecord result=new SecurityModels.IdentityActionRecord(payload);life.check();return result;
    }
    public SecurityModels.IdentityActionRecord reverseAction(String actionId,String reason)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();String suffix=reason==null?"":"?reason="+encode(reason);Map<String,Object>payload=asMap(request(life,"reverseAction","/security/actions/"+encode(actionId)+"/reverse"+suffix,"POST",null));LegacyContracts.action(payload,null,actionId);if(!"Reversed".equals(payload.get("status")))throw LegacyContracts.invalid();SecurityModels.IdentityActionRecord result=new SecurityModels.IdentityActionRecord(payload);life.check();return result;
    }
    public List<SecurityModels.IdentityActionRecord> getActionHistory(String subjectId)throws IOException,InterruptedException{
        RequestLifetime life=new RequestLifetime();List<Object>items=asList(request(life,"getActionHistory","/security/actions/history/"+encode(subjectId),"GET",null));List<SecurityModels.IdentityActionRecord>history=new ArrayList<>();for(Object item:items){LegacyContracts.action(asMap(item),subjectId,null);history.add(new SecurityModels.IdentityActionRecord(asMap(item)));}life.check();return history;
    }

    private Object request(RequestLifetime life,String operation, String path, String method, Object body) throws IOException, InterruptedException
    {
        life.check();HttpClient transport=httpClient;
        if(closed||transport==null||Thread.currentThread().isInterrupted())throw new IOException("Client closed or canceled.");
        emitTrace(life,new AegirDiagnosticsHooks.TraceEvent("request.start",operation,"request.start",OffsetDateTime.now().toString(),null,Map.of("method",method)));
        emitLog(life,new AegirDiagnosticsHooks.LogEntry("information","request.start","Starting "+operation+".",operation,null,OffsetDateTime.now().toString(),Map.of("method",method)));
        HttpRequest.Builder builder=HttpRequest.newBuilder(URI.create(baseUrl+"/v1"+path)).timeout(java.time.Duration.ofNanos(life.remaining())).header("Accept","application/json");
        // Transitional configuration secrets are never client credentials on these identity routes.
        if(developerKey!=null&&!developerKey.isBlank())builder.header("X-Aegir-Developer-Key",developerKey);
        if(body!=null){if("performAction".equals(operation)){Map<String,Object>wire=new java.util.LinkedHashMap<>(IntegrationJson.object(body));wire.put("actionType",LegacyContracts.actionNumber(wire.get("actionType")));body=wire;}String encoded=JsonSupport.stringify(body);if(encoded.length()>1048576)throw LegacyContracts.invalid();builder.header("Content-Type","application/json").method(method,HttpRequest.BodyPublishers.ofString(encoded));}else builder.method(method,HttpRequest.BodyPublishers.noBody());
        java.util.concurrent.CompletableFuture<HttpResponse<byte[]>> task;try{task=transport.sendAsync(builder.build(),info->new LegacyTransport.LimitedBody());}catch(RuntimeException failure){throw new IOException("Aegir transport unavailable.");}pending.add(task);
        long started=System.nanoTime();
        try{
            if(closed)task.cancel(true);
            HttpResponse<byte[]> response=task.get(life.remaining(),java.util.concurrent.TimeUnit.NANOSECONDS);
            String contentType=response.headers().firstValue("Content-Type").orElse("");if(response.headers().allValues("Content-Type").size()!=1||!contentType.matches("(?i)application/json\\s*(;\\s*charset\\s*=\\s*(utf-8|\"utf-8\"))?\\s*"))throw LegacyContracts.invalid();
            String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(response.body())).toString();
            Object payload=JsonSupport.parse(text);String correlation=response.headers().firstValue("X-Correlation-Id").orElse(null);
            if(correlation!=null&&(!correlation.matches("[A-Za-z0-9_.:-]{1,128}")||credentialReflected(correlation)))correlation=null;
            String code=resolveErrorCode(response.statusCode(),payload);
            emitMetric(life,new AegirDiagnosticsHooks.MetricEvent("aegir.client.request.duration",(System.nanoTime()-started)/1000000.0,"ms",OffsetDateTime.now().toString(),Map.of("operation",operation,"status",String.valueOf(response.statusCode()),"errorCode",code)));
            if(response.statusCode()!=200){emitTrace(life,new AegirDiagnosticsHooks.TraceEvent("request.error",operation,"request.error",OffsetDateTime.now().toString(),correlation,Map.of("errorCode",code)));throw new AegirSecurityError("Aegir request failed with status "+response.statusCode()+".",response.statusCode(),code,correlation,null);}
            emitLog(life,new AegirDiagnosticsHooks.LogEntry("information","request.complete","Completed "+operation+".",operation,correlation,OffsetDateTime.now().toString(),Map.of("status","200")));
            emitTrace(life,new AegirDiagnosticsHooks.TraceEvent("request.complete",operation,"request.complete",OffsetDateTime.now().toString(),correlation,Map.of("status","200")));
            life.check();return payload;
        }catch(InterruptedException failure){Thread.currentThread().interrupt();throw new InterruptedException("Aegir request canceled.");}
        catch(AegirSecurityError failure){throw failure;}
        catch(Exception failure){throw new IOException("Aegir response unavailable or invalid.");}
        finally{task.cancel(true);pending.remove(task);}
    }

    private boolean credentialReflected(String value){if(developerKey==null||developerKey.isEmpty())return false;for(String component:developerKey.split(":",-1))if(!component.isEmpty()&&value.contains(component))return true;return false;}
    private void diagnostic(RequestLifetime life,Runnable callback)throws IOException,InterruptedException{
        life.check();java.util.concurrent.Future<?> task;
        try{task=DIAGNOSTICS.submit(callback);}catch(java.util.concurrent.RejectedExecutionException saturated){life.check();return;}
        pendingDiagnostics.add(task);
        try{if(closed)task.cancel(true);task.get(life.remaining(),java.util.concurrent.TimeUnit.NANOSECONDS);}
        catch(java.util.concurrent.ExecutionException callbackFailure){/* Optional host diagnostics never expose a callback cause or change authority. */}
        catch(java.util.concurrent.TimeoutException|java.util.concurrent.CancellationException canceled){throw new IOException("Aegir operation timed out or canceled.");}
        finally{task.cancel(true);pendingDiagnostics.remove(task);}
        life.check();
    }
    private void emitLog(RequestLifetime life,AegirDiagnosticsHooks.LogEntry e)throws IOException,InterruptedException{if(diagnosticsHooks!=null)diagnostic(life,()->diagnosticsHooks.emitLog(e));else life.check();}
    private void emitMetric(RequestLifetime life,AegirDiagnosticsHooks.MetricEvent e)throws IOException,InterruptedException{if(diagnosticsHooks!=null)diagnostic(life,()->diagnosticsHooks.emitMetric(e));else life.check();}
    private void emitTrace(RequestLifetime life,AegirDiagnosticsHooks.TraceEvent e)throws IOException,InterruptedException{if(diagnosticsHooks!=null)diagnostic(life,()->diagnosticsHooks.emitTrace(e));else life.check();}

    private static String resolveErrorCode(int statusCode, Object payload)
    {
        if (payload instanceof Map<?, ?>)
        {
            Map<?, ?> map = (Map<?, ?>) payload;
            Object code = map.get("code");
            if (code instanceof String)
            {
                String text = (String) code;
                if (!text.trim().isEmpty())
                {
                    if(AegirErrorCode.fromCode(text)!=AegirErrorCode.UNKNOWN_ERROR||"unknown_error".equals(text))return AegirErrorCode.fromCode(text).getCode();
                }
            }

            Object error = map.get("error");
            if (error instanceof String)
            {
                String text = (String) error;
                if (!text.trim().isEmpty())
                {
                    if(AegirErrorCode.fromCode(text)!=AegirErrorCode.UNKNOWN_ERROR||"unknown_error".equals(text))return AegirErrorCode.fromCode(text).getCode();
                }
            }
        }

        switch (statusCode)
        {
            case 400:
                return "invalid_request";
            case 401:
                return "unauthorized";
            case 403:
                return "forbidden";
            case 404:
                return "not_found";
            case 409:
                return "conflict";
            case 429:
                return "rate_limited";
            default:
                return statusCode >= 500 ? "server_error" : "unknown_error";
        }
    }

    private static String encode(String value)
    {
        if(!LegacyContracts.input(value,2048,false))throw LegacyContracts.invalid();
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+","%20");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object payload)
    {
        return IntegrationJson.object(payload);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object payload)
    {
        return IntegrationJson.array(payload);
    }

    private static SecurityModels.ScanIdentityResult toScanIdentityResult(Map<String, Object> payload)
    {
        List<SecurityModels.IdentityActionRecord> actionHistory = new ArrayList<>();
        for (Object item : asList(payload.get("actionHistory")))
        {
            actionHistory.add(new SecurityModels.IdentityActionRecord(asMap(item)));
        }

        return new SecurityModels.ScanIdentityResult(
            payload,
            new SecurityModels.IdentityGraphSnapshot(asMap(payload.get("graph"))),
            new SecurityModels.ExposureSummary(asMap(payload.get("exposure"))),
            actionHistory);
    }
}
