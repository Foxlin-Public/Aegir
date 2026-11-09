// Copyright Foxlin Industries. Unreleased RC1 server integration; not cryptography.
package cloud.foxlin.aegir.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Genuine backend consumer. Events invalidate state; only fresh server checks permit operations. */
public final class AuthorizationIntegration implements AutoCloseable {
    static final Set<String> KNOWN=Collections.unmodifiableSet(new HashSet<>(Arrays.asList("granted","revoked","adminGranted","adminRevoked","permissionChanged","licenseGranted","licenseRevoked","membershipChanged","suspended","restored","groupPolicyChanged")));
    private final URI api,web;
    private final String credential,organizationId,applicationId;
    private final Journal journal;
    private final HttpClient client;
    private final ExecutorService executor;
    private final Duration timeout;
    private final Set<CompletableFuture<?>> pending=ConcurrentHashMap.newKeySet();
    private final ReentrantLock processing=new ReentrantLock();
    private volatile boolean closed;
    private boolean connected;

    /** Host-owned durable transaction boundary for receipts, versions and invalidation effects. */
    public interface Journal extends AutoCloseable {
        void bind(String streamBinding) throws Exception;
        ApplyResult apply(List<Notification> events) throws Exception;
        void applySnapshot(Snapshot snapshot) throws Exception;
        void setConnected(boolean connected) throws Exception;
        JournalStats stats() throws Exception;
        void close() throws Exception;
    }
    public static final class ApplyResult {
        public final int newEffects; public final boolean requiresSnapshot;
        public ApplyResult(int effects,boolean snapshot){newEffects=effects;requiresSnapshot=snapshot;}
    }
    public static final class JournalStats {
        public final int receipts,effects;public final boolean connected;
        public JournalStats(int receipts,int effects,boolean connected){this.receipts=receipts;this.effects=effects;this.connected=connected;}
    }
    public static final class Notification {
        public final long protocolVersion,groupVersion;
        public final String transactionId,eventId,groupId,userId,eventType;
        public Notification(long protocolVersion,String transactionId,String eventId,String groupId,String userId,String eventType,long groupVersion){this.protocolVersion=protocolVersion;this.transactionId=transactionId;this.eventId=eventId;this.groupId=groupId;this.userId=userId;this.eventType=eventType;this.groupVersion=groupVersion;}
        static Notification parse(Object value){Map<String,Object> m=IntegrationJson.object(value);IntegrationJson.required(m,"protocolVersion","transactionId","eventId","groupId","userId","eventType","groupVersion");if(m.size()!=7)throw IntegrationJson.invalid();return new Notification(IntegrationJson.integer(m.get("protocolVersion"),1),IntegrationJson.string(m.get("transactionId"),512),IntegrationJson.string(m.get("eventId"),512),IntegrationJson.string(m.get("groupId"),512),m.get("userId")==null?null:IntegrationJson.string(m.get("userId"),512),IntegrationJson.string(m.get("eventType"),64),IntegrationJson.integer(m.get("groupVersion"),1));}
        Map<String,Object> json(){Map<String,Object> m=new LinkedHashMap<>();m.put("protocolVersion",protocolVersion);m.put("transactionId",transactionId);m.put("eventId",eventId);m.put("groupId",groupId);m.put("userId",userId);m.put("eventType",eventType);m.put("groupVersion",groupVersion);return m;}
    }
    public static final class Snapshot {
        public final String snapshotId;
        public final List<SnapshotGroup> groups;
        public Snapshot(String id,List<SnapshotGroup> groups){snapshotId=id;this.groups=Collections.unmodifiableList(new ArrayList<>(groups));}
        static Snapshot parse(Object value){Map<String,Object> m=IntegrationJson.object(value);IntegrationJson.required(m,"snapshotId","groups");List<SnapshotGroup> groups=new ArrayList<>();for(Object raw:IntegrationJson.array(m.get("groups"))){Map<String,Object> g=IntegrationJson.object(raw);IntegrationJson.required(g,"groupId","groupVersion","subjects");List<SnapshotSubject> subjects=new ArrayList<>();for(Object sub:IntegrationJson.array(g.get("subjects"))){Map<String,Object>s=IntegrationJson.object(sub);IntegrationJson.required(s,"userId","allowed","authorizationEpoch");subjects.add(new SnapshotSubject(IntegrationJson.string(s.get("userId"),512),IntegrationJson.bool(s.get("allowed")),IntegrationJson.integer(s.get("authorizationEpoch"),0)));}groups.add(new SnapshotGroup(IntegrationJson.string(g.get("groupId"),512),IntegrationJson.integer(g.get("groupVersion"),0),subjects));}return new Snapshot(IntegrationJson.string(m.get("snapshotId"),512),groups);}
    }
    public static final class SnapshotGroup {
        public final String groupId; public final long groupVersion; public final List<SnapshotSubject> subjects;
        public SnapshotGroup(String id,long version,List<SnapshotSubject> subjects){groupId=id;groupVersion=version;this.subjects=Collections.unmodifiableList(new ArrayList<>(subjects));}
    }
    public static final class SnapshotSubject {
        public final String userId;public final boolean allowed;public final long authorizationEpoch;
        public SnapshotSubject(String userId,boolean allowed,long epoch){this.userId=userId;this.allowed=allowed;authorizationEpoch=epoch;}
    }
    public static final class Decision {
        public final boolean isAuthorized;public final String reason,applicationSubjectId;public final long authorizationEpoch;public final List<String> effectiveGroupIds,permissions;
        private Decision(boolean allowed,String reason,String alias,long epoch,List<String> groups,List<String> permissions){isAuthorized=allowed;this.reason=reason;applicationSubjectId=alias;authorizationEpoch=epoch;effectiveGroupIds=Collections.unmodifiableList(new ArrayList<>(groups));this.permissions=Collections.unmodifiableList(new ArrayList<>(permissions));}
        static Decision denied(String reason){return new Decision(false,reason,null,0,Collections.emptyList(),Collections.emptyList());}
    }
    public static final class FreshAuthentication {
        private final String accessToken;
        public final String challengeId;public final boolean mfaRequired;public final Instant expiresAtUtc;
        private FreshAuthentication(String token,String challenge,boolean mfa,Instant expires){accessToken=token;challengeId=challenge;mfaRequired=mfa;expiresAtUtc=expires;}
        /** Sensitive scoped ticket. Never log it or send the backend credential to a browser. */
        public String accessToken(){return accessToken;}
        @Override public String toString(){return "AegirFreshAuthentication(<redacted>)";}
    }
    @FunctionalInterface public interface ProtectedEffect { void run() throws Exception; }

    /** Uses normal TLS validation. Owns its client; redirects, cookies and proxies are disabled. */
    public AuthorizationIntegration(URI api,URI web,String credential,String organizationId,String applicationId,Journal journal) throws Exception {
        this(api,web,credential,organizationId,applicationId,journal,null,Duration.ofSeconds(15));
    }
    /** Exact-certificate development pin is restricted to clean HTTPS loopback addresses only. */
    public static AuthorizationIntegration pinnedLoopbackDevelopment(URI api,URI web,String credential,String organizationId,String applicationId,Journal journal,String certificateSha256,Duration timeout) throws Exception {
        if(certificateSha256==null||!certificateSha256.matches("[a-fA-F0-9]{64}")||!loopback(api)||!loopback(web))throw new IllegalArgumentException("Exact SHA256 and HTTPS loopback endpoints required.");
        return new AuthorizationIntegration(api,web,credential,organizationId,applicationId,journal,certificateSha256,timeout);
    }
    private AuthorizationIntegration(URI api,URI web,String credential,String organizationId,String applicationId,Journal journal,String pin,Duration timeout) throws Exception {
        cleanBase(api);cleanBase(web);IntegrationJson.string(credential,512);IntegrationJson.string(organizationId,128);IntegrationJson.string(applicationId,128);
        if(journal==null||timeout==null||timeout.isZero()||timeout.isNegative()||timeout.compareTo(Duration.ofSeconds(30))>0)throw new IllegalArgumentException("Durable journal and bounded timeout required.");
        this.api=api;this.web=web;this.credential=credential;this.organizationId=organizationId;this.applicationId=applicationId;this.journal=journal;this.timeout=timeout;
        executor=Executors.newFixedThreadPool(2,r->{Thread t=new Thread(r,"aegir-integration-transport");t.setDaemon(true);return t;});
        HttpClient.Builder builder=HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(timeout).executor(executor).proxy(new ProxySelector(){@Override public List<Proxy> select(URI uri){return Collections.singletonList(Proxy.NO_PROXY);}@Override public void connectFailed(URI uri,SocketAddress address,IOException failure){}});
        try {
            if(pin!=null){byte[] expected=unhex(pin);SSLContext context=SSLContext.getInstance("TLS");context.init(null,new TrustManager[]{new X509TrustManager(){public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}public void checkClientTrusted(X509Certificate[] chain,String auth)throws CertificateException{throw new CertificateException("Client certificate not supported.");}public void checkServerTrusted(X509Certificate[] chain,String auth)throws CertificateException{try{if(chain==null||chain.length==0||!MessageDigest.isEqual(expected,MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded())))throw new CertificateException("Development certificate pin mismatch.");}catch(CertificateException failure){throw failure;}catch(Exception failure){throw new CertificateException("Development certificate unavailable.");}}}},null);builder.sslContext(context);}
            client=builder.build();journal.bind(hex(MessageDigest.getInstance("SHA-256").digest((api.toString()+"\n"+organizationId+"\n"+applicationId).getBytes(StandardCharsets.UTF_8))));journal.setConnected(false);
        }catch(Exception failure){executor.shutdownNow();throw failure;}
    }
    private static boolean loopback(URI uri){if(uri==null)return false;String h=uri.getHost();return "localhost".equals(h)||"127.0.0.1".equals(h)||"[::1]".equals(h)||"::1".equals(h);}
    private static void cleanBase(URI uri){if(uri==null||!uri.isAbsolute()||!"https".equals(uri.getScheme())||uri.getHost()==null||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||!uri.getPath().endsWith("/")||uri.getRawPath().indexOf('%')>=0)throw new IllegalArgumentException("Clean HTTPS base ending in slash required.");}
    static byte[] unhex(String value){byte[] bytes=new byte[value.length()/2];for(int i=0;i<bytes.length;i++)bytes[i]=(byte)Integer.parseInt(value.substring(i*2,i*2+2),16);return bytes;}
    static String hex(byte[] bytes){StringBuilder value=new StringBuilder();for(byte b:bytes)value.append(String.format("%02x",b&255));return value.toString();}
    private static final class Response {final int status;final Map<String,Object> json;Response(int status,Map<String,Object> json){this.status=status;this.json=json;}}
    private Response request(boolean webRequest,String method,String path,Object payload) throws Exception {
        if(closed||Thread.currentThread().isInterrupted())throw new IOException("Integration closed or canceled.");
        HttpRequest.Builder builder=HttpRequest.newBuilder((webRequest?web:api).resolve(path)).timeout(timeout).header("Accept","application/json");
        if(!webRequest)builder.header("X-Aegir-Application-Key",credential);
        if(payload==null)builder.method(method,HttpRequest.BodyPublishers.noBody());else builder.header("Content-Type","application/json").method(method,HttpRequest.BodyPublishers.ofString(IntegrationJson.stringify(payload)));
        CompletableFuture<HttpResponse<byte[]>> task=client.sendAsync(builder.build(),info->new LimitedBody());pending.add(task);
        try {
            if(closed)task.cancel(true);
            HttpResponse<byte[]> response=task.get(timeout.toMillis(),TimeUnit.MILLISECONDS);
            Map<String,Object> object=Collections.emptyMap();
            if(response.body().length>0){String contentType=response.headers().firstValue("Content-Type").orElse("");if(!contentType.split(";",2)[0].trim().equalsIgnoreCase("application/json"))throw new IOException("JSON response required.");String body=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(response.body())).toString();object=IntegrationJson.object(IntegrationJson.parse(body));}
            return new Response(response.statusCode(),object);
        }catch(InterruptedException failure){Thread.currentThread().interrupt();throw new IOException("Integration request canceled.");}
        catch(Exception failure){throw new IOException("Authoritative request failed.");}
        finally {task.cancel(true);pending.remove(task);}
    }
    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result=new CompletableFuture<>();private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();private Flow.Subscription subscription;
        public java.util.concurrent.CompletionStage<byte[]> getBody(){return result;}
        public void onSubscribe(Flow.Subscription sub){subscription=sub;sub.request(1);}
        public void onNext(List<ByteBuffer> buffers){for(ByteBuffer buffer:buffers){if(bytes.size()+buffer.remaining()>1048576){subscription.cancel();result.completeExceptionally(new IOException("Authority response too large."));return;}byte[] part=new byte[buffer.remaining()];buffer.get(part);bytes.write(part,0,part.length);}subscription.request(1);}
        public void onError(Throwable failure){result.completeExceptionally(new IOException("Authority response unavailable."));}
        public void onComplete(){result.complete(bytes.toByteArray());}
    }
    /** Actual Web password/MFA exchange; no preexisting JWT or event can substitute. */
    public FreshAuthentication authenticateFresh(String username,String password,String challengeId,String totpCode) throws Exception {
        IntegrationJson.string(username,320);IntegrationJson.string(password,2048);
        Map<String,Object> body=new LinkedHashMap<>();body.put("username",username);body.put("password",password);body.put("organizationId",organizationId);body.put("applicationId",applicationId);body.put("challengeId",challengeId);body.put("totpCode",totpCode);
        Response response=request(true,"POST","account/organization-access",body);
        if(response.status==400&&"mfa_required".equals(response.json.get("error")))return new FreshAuthentication(null,IntegrationJson.string(response.json.get("challengeId"),512),true,null);
        if(response.status!=200)throw new IOException("Fresh authentication denied.");
        Map<String,Object> m=response.json;IntegrationJson.required(m,"accessToken","expiresAtUtc","organizationId","applicationId","subjectId","authorizationEpoch");
        if(!organizationId.equals(m.get("organizationId"))||!applicationId.equals(m.get("applicationId")))throw IntegrationJson.invalid();IntegrationJson.string(m.get("subjectId"),128);IntegrationJson.integer(m.get("authorizationEpoch"),0);
        Instant expires=OffsetDateTime.parse(IntegrationJson.string(m.get("expiresAtUtc"),64),DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();if(!expires.isAfter(Instant.now()))throw IntegrationJson.invalid();
        return new FreshAuthentication(IntegrationJson.string(m.get("accessToken"),512),null,false,expires);
    }
    private void disconnected(){connected=false;try{journal.setConnected(false);}catch(Exception ignored){/* In-memory state still denies; next journal operation cannot silently succeed. */}}
    /** Starts fail-closed, then drains authenticated replay or reconciles a server-issued snapshot. */
    public void reconnect() throws Exception {processing.lockInterruptibly();try{disconnected();drain(true);disconnected();snapshot();drain(true);}catch(Exception failure){disconnected();throw failure;}finally{processing.unlock();}}
    /** Healthy routine polling does not clear connected state; any failure does. */
    public void poll() throws Exception {poll(true);}
    /** False models a lost ACK: persist the batch but require reconciliation before another operation. */
    public void poll(boolean acknowledge) throws Exception {processing.lockInterruptibly();try{if(!connected)throw new IOException("Event reconciliation required.");drain(acknowledge);}finally{processing.unlock();}}
    private void snapshot() throws Exception {
        Response response=request(false,"GET","v1/authorization/snapshot",null);if(response.status!=200)throw new IOException("Snapshot denied.");Snapshot snapshot=Snapshot.parse(response.json);journal.applySnapshot(snapshot);
        response=request(false,"POST","v1/authorization/snapshot/ack",Collections.singletonMap("snapshotId",snapshot.snapshotId));if(response.status!=204)throw new IOException("Snapshot acknowledgment denied.");
    }
    private void drain(boolean acknowledge) throws Exception {
        try{for(int attempt=0;attempt<20;attempt++){
            Response response=request(false,"GET","v1/authorization/events?limit=100",null);if(response.status!=200)throw new IOException("Event poll denied.");Map<String,Object> m=response.json;IntegrationJson.required(m,"deliveryId","events","requiresSnapshot","reason","retryAfterSeconds");
            boolean requires=IntegrationJson.bool(m.get("requiresSnapshot"));long retry=IntegrationJson.integer(m.get("retryAfterSeconds"),0);if(retry>30)throw IntegrationJson.invalid();String reason=m.get("reason")==null?null:IntegrationJson.string(m.get("reason"),256);String delivery=m.get("deliveryId")==null?null:IntegrationJson.string(m.get("deliveryId"),512);
            List<Notification> events=new ArrayList<>();for(Object event:IntegrationJson.array(m.get("events"))){if(events.size()>=100)throw IntegrationJson.invalid();events.add(Notification.parse(event));}
            if(requires){disconnected();snapshot();continue;}
            if("retry_backoff".equals(reason)){long delay=Math.max(1,retry)*1000;for(long waited=0;waited<delay;waited+=50){if(closed)throw new IOException("Integration closed.");Thread.sleep(Math.min(50,delay-waited));}continue;}
            if(events.isEmpty()){journal.setConnected(true);connected=true;return;}
            if(delivery==null)throw IntegrationJson.invalid();ApplyResult applied=journal.apply(events);
            if(applied.requiresSnapshot){disconnected();snapshot();continue;}
            if(!acknowledge){disconnected();return;}
            response=request(false,"POST","v1/authorization/ack",Collections.singletonMap("deliveryId",delivery));if(response.status!=204)throw new IOException("Acknowledgment denied.");
        }throw new IOException("Bounded replay attempts exhausted.");}catch(Exception failure){disconnected();throw failure;}
    }
    /** Fresh authority for exactly read or write. Never cache this result for another operation. */
    public Decision authorize(String ticket,String operation,String expectedSubjectAlias){
        boolean locked=false;
        try{
            processing.lockInterruptibly();locked=true;if(closed||Thread.currentThread().isInterrupted())return Decision.denied("operation_canceled");
            if(!"read".equals(operation)&&!"write".equals(operation))return Decision.denied("unsupported_operation");
            IntegrationJson.string(ticket,512);if(!connected)return Decision.denied("event_reconciliation_required");
            Map<String,Object> body=new LinkedHashMap<>();body.put("accessToken",ticket);body.put("operation",operation);
            Response response=request(false,"POST","v1/authorization/check",body);Map<String,Object> m=response.json;
            IntegrationJson.required(m,"isAuthorized","reason","applicationSubjectId","authorizationEpoch","effectiveGroupIds","permissions");
            boolean allowed=IntegrationJson.bool(m.get("isAuthorized"));String reason=IntegrationJson.string(m.get("reason"),256);long epoch=IntegrationJson.integer(m.get("authorizationEpoch"),0);
            List<String> groups=strings(m.get("effectiveGroupIds"),100),permissions=strings(m.get("permissions"),2);
            String alias=m.get("applicationSubjectId")==null?null:IntegrationJson.string(m.get("applicationSubjectId"),512);
            if((allowed&&response.status!=200)||(!allowed&&(response.status!=403||"authorized".equals(reason)))||permissions.stream().anyMatch(p->!p.equals("read")&&!p.equals("write"))||(allowed&&(!"authorized".equals(reason)||alias==null||groups.isEmpty()||!permissions.contains(operation)||(expectedSubjectAlias!=null&&!expectedSubjectAlias.isEmpty()&&!expectedSubjectAlias.equals(alias)))))throw IntegrationJson.invalid();
            if(!allowed&&reason.equals("event_reconciliation_required"))disconnected();return new Decision(allowed,reason,alias,epoch,groups,permissions);
        }catch(InterruptedException failure){Thread.currentThread().interrupt();if(locked)disconnected();return Decision.denied("operation_canceled");}
        catch(Exception failure){if(locked)disconnected();return Decision.denied("authoritative_access_unavailable");}
        finally{if(locked)processing.unlock();}
    }
    private static List<String> strings(Object value,int maximum){List<String> result=new ArrayList<>();for(Object raw:IntegrationJson.array(value)){if(result.size()>=maximum)throw IntegrationJson.invalid();String text=IntegrationJson.string(raw,512);if(result.contains(text))throw IntegrationJson.invalid();result.add(text);}return result;}
    /** Invokes effect only after a fresh permit. The host must revalidate before its own commit. */
    public Decision executeProtected(String ticket,String operation,String expectedSubjectAlias,ProtectedEffect effect) throws Exception {
        if(effect==null)throw new IllegalArgumentException("Protected callback required.");Decision decision=authorize(ticket,operation,expectedSubjectAlias);if(decision.isAuthorized){if(closed||Thread.currentThread().isInterrupted())return Decision.denied("operation_canceled");effect.run();}return decision;
    }
    /** Ordinary revalidation, not an atomic fence against later cross-database revocation. */
    public Decision beforeCommit(String ticket,String operation,String expectedSubjectAlias) throws Exception {Decision d=authorize(ticket,operation,expectedSubjectAlias);if(!d.isAuthorized)throw new IOException("Protected commit denied.");return d;}
    public void disconnect(){processing.lock();try{disconnected();}finally{processing.unlock();}}
    /** Cancels in-flight requests, closes the owned journal, and joins owned executor threads. */
    @Override public void close() throws Exception {
        if(closed)return;closed=true;for(CompletableFuture<?> task:pending)task.cancel(true);processing.lock();
        try{disconnected();journal.close();}finally{processing.unlock();executor.shutdownNow();if(!executor.awaitTermination(5,TimeUnit.SECONDS))throw new IOException("Transport shutdown timed out.");}
    }
}
