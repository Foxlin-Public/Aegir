// Copyright Foxlin Industries. Native adversarial tests, separate from real-host parity.
package cloud.foxlin.aegir.security;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public final class AuthorizationIntegrationTest {
    private static int passed;
    private static Path keyStore;
    private static final String VALID="{\"isAuthorized\":true,\"reason\":\"authorized\",\"applicationSubjectId\":\"opaque-subject\",\"authorizationEpoch\":0,\"effectiveGroupIds\":[\"opaque-group\"],\"permissions\":[\"read\",\"write\"]}";
    @FunctionalInterface private interface Test {void run() throws Exception;}
    private static void test(String name,Test test)throws Exception{test.run();passed++;System.out.println("PASS "+name);}
    private static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
    private static void reject(Test test,String reason)throws Exception{try{test.run();}catch(Exception expected){return;}throw new AssertionError(reason);}
    public static void main(String[] args)throws Exception{
        keyStore=Path.of(args[0]);
        test("strict-json",()->{for(String text:Arrays.asList("{\"a\":1,\"a\":2}","{\"a\":true}{}","{\"a\":tru}","{\"a\":1,}"))reject(()->IntegrationJson.parse(text),"Malformed JSON accepted");});
        test("journal-atomic-dedup-ordering-restart",AuthorizationIntegrationTest::journal);
        test("journal-lock-and-corruption",AuthorizationIntegrationTest::journalLock);
        test("secure-configuration",AuthorizationIntegrationTest::configuration);
        test("current-check-and-revalidation",()->{try(Fixture f=new Fixture()){f.client.reconnect();AtomicInteger effects=new AtomicInteger();AuthorizationIntegration.Decision d=f.client.executeProtected("ticket","write","opaque-subject",()->{f.client.beforeCommit("ticket","write","opaque-subject");effects.incrementAndGet();});check(d.isAuthorized&&effects.get()==1&&f.checks.get()==2,"Fresh/revalidation checks missing");f.client.poll();check(f.client.authorize("ticket","read",null).isAuthorized,"Healthy poll disabled authority");}});
        test("fresh-auth-offset-timestamp",()->{try(Fixture f=new Fixture()){AuthorizationIntegration.FreshAuthentication auth=f.client.authenticateFresh("synthetic-user","synthetic-password",null,null);check(!auth.mfaRequired&&auth.accessToken()!=null&&auth.expiresAtUtc.isAfter(java.time.Instant.now()),"Actual .NET offset timestamp rejected");}});
        test("fresh-auth-foreign-binding-and-null-epoch",()->{try(Fixture f=new Fixture()){f.authBody=f.authBody.replace("\"organizationId\":\"org\"","\"organizationId\":\"unrelated-org\"");reject(()->f.client.authenticateFresh("synthetic-user","synthetic-password",null,null),"Foreign organization accepted");f.authBody=f.authBody.replace("\"organizationId\":\"unrelated-org\"","\"organizationId\":\"org\"").replace("\"authorizationEpoch\":0","\"authorizationEpoch\":null");reject(()->f.client.authenticateFresh("synthetic-user","synthetic-password",null,null),"Null authentication epoch accepted");}});
        Map<String,String> invalid=new LinkedHashMap<>();invalid.put("contradictory-reason",VALID.replace("\"authorized\"","\"license_required\""));invalid.put("missing-reason",VALID.replace("\"reason\":\"authorized\",",""));invalid.put("null-epoch",VALID.replace("\"authorizationEpoch\":0","\"authorizationEpoch\":null"));invalid.put("null-alias",VALID.replace("\"opaque-subject\"","null"));invalid.put("empty-groups",VALID.replace("[\"opaque-group\"]","[]"));invalid.put("wrong-permission",VALID.replace("[\"read\",\"write\"]","[\"read\"]"));invalid.put("duplicate-property",VALID.replace("\"isAuthorized\":true","\"isAuthorized\":false,\"isAuthorized\":true"));invalid.put("trailing-json",VALID+"{}");invalid.put("wrong-casing",VALID.replace("\"isAuthorized\"","\"IsAuthorized\""));
        for(Map.Entry<String,String> item:invalid.entrySet())test(item.getKey(),()->{try(Fixture f=new Fixture()){f.client.reconnect();f.body=item.getValue();AtomicInteger effects=new AtomicInteger();check(!f.client.executeProtected("ticket","write",null,effects::incrementAndGet).isAuthorized&&effects.get()==0,"Malformed authority ran effect");}});
        test("forbidden-permit",()->{try(Fixture f=new Fixture()){f.client.reconnect();f.status=403;check(!f.client.authorize("ticket","read",null).isAuthorized,"403 permit accepted");}});
        test("alias-and-scope",()->{try(Fixture f=new Fixture()){f.client.reconnect();check(!f.client.authorize("ticket","read","unrelated").isAuthorized,"Subject substitution accepted");f.client.reconnect();check(!f.client.authorize("ticket","delete",null).isAuthorized,"Unsupported permission accepted");}});
        test("redirect-not-followed",()->{try(Fixture f=new Fixture()){f.client.reconnect();f.status=307;check(!f.client.authorize("ticket","read",null).isAuthorized&&f.redirects.get()==0,"Redirect followed");}});
        test("wrong-response-media-type",()->{try(Fixture f=new Fixture()){f.client.reconnect();f.contentType="application/jsonp";AtomicInteger effects=new AtomicInteger();check(!f.client.executeProtected("ticket","write",null,effects::incrementAndGet).isAuthorized&&effects.get()==0,"Wrong MIME type permitted callback");}});
        test("wrong-pin",()->{try(Fixture f=new Fixture()){FileAuthorizationJournal j=new FileAuthorizationJournal(Files.createTempDirectory("aegir-wrongpin-").resolve("journal"));try(AuthorizationIntegration c=AuthorizationIntegration.pinnedLoopbackDevelopment(f.base,f.base,"credential","org","app",j,String.join("",Collections.nCopies(64,"0")),Duration.ofMillis(500))){reject(c::reconnect,"Wrong certificate accepted");}}});
        test("cancel-close-no-owned-threads",AuthorizationIntegrationTest::cancellation);
        System.out.println("{\"suite\":\"java-authorization-native\",\"passed\":"+passed+",\"failed\":0,\"skipped\":0}");
    }
    private static AuthorizationIntegration.Notification event(String id,String type,long version){return new AuthorizationIntegration.Notification(1,"same-transaction",id,"group-alias",null,type,version);}
    private static void journal()throws Exception{
        Path path=Files.createTempDirectory("aegir-journal-").resolve("journal.json");String binding=String.join("",Collections.nCopies(64,"a"));
        List<AuthorizationIntegration.Notification> events=Arrays.asList(event("event-1","granted",1),event("event-2","membershipChanged",1),event("event-3","revoked",2));
        try(FileAuthorizationJournal j=new FileAuthorizationJournal(path)){
            j.bind(binding);check(j.apply(events).newEffects==3,"Same-transaction independent events lost");check(j.apply(events).newEffects==0,"Duplicate effects");check(j.apply(Collections.singletonList(event("late-grant","granted",1))).newEffects==0,"Late grant effect");
            check(j.apply(Arrays.asList(event("would-apply","revoked",3),event("unknown","future",4))).requiresSnapshot,"Unknown type accepted");check(j.stats().receipts==4&&j.stats().effects==3,"Partial batch committed");
            reject(()->j.apply(Collections.singletonList(event("event-3","granted",2))),"Contradictory duplicate accepted");
            reject(()->j.applySnapshot(new AuthorizationIntegration.Snapshot("old",Collections.singletonList(new AuthorizationIntegration.SnapshotGroup("group-alias",1,Collections.emptyList())))),"Snapshot rollback accepted");
        }
        try(FileAuthorizationJournal j=new FileAuthorizationJournal(path)){j.bind(binding);check(j.stats().receipts==4&&j.stats().effects==3&&!j.stats().connected,"Restart lost state");check(j.apply(events).newEffects==0,"Restart dedup failed");reject(()->j.bind(String.join("",Collections.nCopies(64,"b"))),"Cross-application journal accepted");}
    }
    private static void journalLock()throws Exception{
        Path path=Files.createTempDirectory("aegir-journal-lock-").resolve("journal");
        try(FileAuthorizationJournal j=new FileAuthorizationJournal(path)){reject(()->{try(FileAuthorizationJournal second=new FileAuthorizationJournal(path)){throw new AssertionError("Second writer");}},"Second writer accepted");Thread.currentThread().interrupt();try{reject(()->j.apply(Collections.singletonList(event("canceled","revoked",1))),"Interrupted transaction committed");}finally{Thread.interrupted();}check(j.stats().effects==0,"Interrupted effect");}
        String content=Files.readString(path);content=content.replaceFirst("\"sha256\":\"[a-f0-9]{64}\"","\"sha256\":\""+String.join("",Collections.nCopies(64,"0"))+"\"");Files.writeString(path,content);
        reject(()->{try(FileAuthorizationJournal j=new FileAuthorizationJournal(path)){throw new AssertionError("Corrupt journal");}},"Corrupt journal accepted");
    }
    private static void configuration()throws Exception{
        for(String raw:Arrays.asList("http://127.0.0.1/","https://user:password@example.test/","https://example.test/path?token=x","https://example.test"))try(FileAuthorizationJournal j=new FileAuthorizationJournal(Files.createTempDirectory("aegir-invalid-").resolve("journal"))){reject(()->new AuthorizationIntegration(URI.create(raw),URI.create(raw),"credential","org","app",j),"Unsafe transport accepted");}
        try(FileAuthorizationJournal j=new FileAuthorizationJournal(Files.createTempDirectory("aegir-foreign-pin-").resolve("journal"))){reject(()->AuthorizationIntegration.pinnedLoopbackDevelopment(URI.create("https://example.test/"),URI.create("https://example.test/"),"credential","org","app",j,String.join("",Collections.nCopies(64,"0")),Duration.ofSeconds(1)),"Foreign development pin accepted");}
    }
    private static void cancellation()throws Exception{
        try(Fixture f=new Fixture()){
            f.client.reconnect();f.block.set(true);AtomicBoolean permitted=new AtomicBoolean(true);Thread worker=new Thread(()->permitted.set(f.client.authorize("ticket","read",null).isAuthorized),"aegir-native-check");worker.start();long deadline=System.nanoTime()+2_000_000_000L;while(f.checks.get()==0&&System.nanoTime()<deadline)Thread.sleep(5);
            long start=System.nanoTime();f.client.close();worker.join(2000);check(!worker.isAlive()&&!permitted.get()&&(System.nanoTime()-start)<2_000_000_000L,"Close failed to cancel active request");
        }
        Thread.sleep(100);for(Thread thread:Thread.getAllStackTraces().keySet())check(!thread.isAlive()||!thread.getName().equals("aegir-integration-transport"),"Owned transport thread leaked");
    }
    private static final class Fixture implements AutoCloseable {
        final HttpsServer server;final ExecutorService workers=Executors.newFixedThreadPool(2);final URI base;final AuthorizationIntegration client;final AtomicInteger checks=new AtomicInteger(),redirects=new AtomicInteger();final AtomicBoolean block=new AtomicBoolean();volatile String body=VALID;volatile int status=200;volatile String authBody;volatile String contentType="application/json";
        Fixture()throws Exception{
            String expires=java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).plusMinutes(5).format(java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSSSxxx"));
            authBody="{\"accessToken\":\"synthetic-ticket-only\",\"expiresAtUtc\":\""+expires+"\",\"organizationId\":\"org\",\"applicationId\":\"app\",\"subjectId\":\"synthetic-subject\",\"authorizationEpoch\":0}";
            char[] password=System.getenv("AEGIR_JAVA_TEST_KEYSTORE_PASS").toCharArray();KeyStore store=KeyStore.getInstance("PKCS12");try(java.io.InputStream input=Files.newInputStream(keyStore)){store.load(input,password);}KeyManagerFactory keys=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());keys.init(store,password);java.util.Arrays.fill(password,'\0');SSLContext tls=SSLContext.getInstance("TLS");tls.init(keys.getKeyManagers(),null,null);
            server=HttpsServer.create(new InetSocketAddress("127.0.0.1",0),0);server.setHttpsConfigurator(new HttpsConfigurator(tls));server.setExecutor(workers);server.createContext("/",this::handle);server.start();base=URI.create("https://127.0.0.1:"+server.getAddress().getPort()+"/");String pin=AuthorizationIntegration.hex(MessageDigest.getInstance("SHA-256").digest(store.getCertificate("aegir-test").getEncoded()));
            FileAuthorizationJournal journal=null;try{journal=new FileAuthorizationJournal(Files.createTempDirectory("aegir-transport-").resolve("journal"));client=AuthorizationIntegration.pinnedLoopbackDevelopment(base,base,"credential","org","app",journal,pin,Duration.ofSeconds(2));}catch(Exception failure){if(journal!=null)try{journal.close();}catch(Exception ignored){}server.stop(0);workers.shutdownNow();throw failure;}
        }
        void handle(HttpExchange exchange)throws java.io.IOException{
            String path=exchange.getRequestURI().getPath(),response="";int code=200;
            switch(path){case "/account/organization-access":response=authBody;break;case "/v1/authorization/events":response="{\"deliveryId\":null,\"events\":[],\"requiresSnapshot\":false,\"reason\":null,\"retryAfterSeconds\":0}";break;case "/v1/authorization/snapshot":response="{\"snapshotId\":\"snapshot-current\",\"groups\":[]}";break;case "/v1/authorization/snapshot/ack":code=204;break;case "/v1/authorization/check":checks.incrementAndGet();if(block.get()){try{Thread.sleep(1500);}catch(InterruptedException canceled){Thread.currentThread().interrupt();}}response=body;code=status;if(code==307)exchange.getResponseHeaders().set("Location",base.resolve("redirect-target").toString());break;case "/redirect-target":redirects.incrementAndGet();response=VALID;break;default:code=404;}
            exchange.getResponseHeaders().set("Content-Type",contentType);byte[] bytes=response.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(code,code==204?-1:bytes.length);if(code!=204)exchange.getResponseBody().write(bytes);exchange.close();
        }
        @Override public void close()throws Exception{try{client.close();}finally{server.stop(0);workers.shutdownNow();workers.awaitTermination(3,java.util.concurrent.TimeUnit.SECONDS);}}
    }
}
