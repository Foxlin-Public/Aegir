// Copyright Foxlin Industries. Local line-JSON example and real-server runner.
package cloud.foxlin.aegir.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/** Reads a private config path and private commands; never prints tickets or passwords. */
public final class IntegrationScenario {
    private IntegrationScenario() { }
    public static void main(String[] args) {
        try { run(args); }
        catch(Exception failure){System.err.println("Aegir integration runner failed; inspect private configuration and local service state.");System.exit(1);}
    }
    private static void run(String[] args) throws Exception {
        if(args.length!=1||Files.size(Path.of(args[0]))>65536)throw new IllegalArgumentException("Private configuration path required.");
        Map<String,Object> config=IntegrationJson.object(IntegrationJson.parse(Files.readString(Path.of(args[0]),StandardCharsets.UTF_8)));
        URI api=URI.create(IntegrationJson.string(config.get("apiBaseUrl"),2048)),web=URI.create(IntegrationJson.string(config.get("webBaseUrl"),2048));
        String organization=IntegrationJson.string(config.get("organizationId"),128),application=IntegrationJson.string(config.get("applicationId"),128),credential=IntegrationJson.string(config.get("applicationCredential"),512),username=IntegrationJson.string(config.get("username"),320),password=IntegrationJson.string(config.get("password"),2048);
        int timeout=config.containsKey("timeoutMs")?Math.toIntExact(IntegrationJson.integer(config.get("timeoutMs"),1)):15000;
        FileAuthorizationJournal journal=new FileAuthorizationJournal(Path.of(IntegrationJson.string(config.get("journalPath"),4096)));
        AuthorizationIntegration created;
        try{
            if(config.get("certificateSha256")!=null)created=AuthorizationIntegration.pinnedLoopbackDevelopment(api,web,credential,organization,application,journal,IntegrationJson.string(config.get("certificateSha256"),64),Duration.ofMillis(timeout));
            else created=new AuthorizationIntegration(api,web,credential,organization,application,journal);
        }catch(Exception failure){journal.close();throw failure;}
        ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegir-example-deadline");t.setDaemon(true);return t;});
        String ticket=null;
        try(AuthorizationIntegration client=created;BufferedReader input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8))){
            String line;
            while((line=input.readLine())!=null){
                Map<String,Object> result=new LinkedHashMap<>();result.put("ok",false);Map<String,Object> command;
                try{if(line.length()>65536)throw IntegrationJson.invalid();command=IntegrationJson.object(IntegrationJson.parse(line));}
                catch(Exception invalid){result.put("reason","invalid_command");System.out.println(IntegrationJson.stringify(result));continue;}
                result.put("requestId",command.get("requestId"));String op=IntegrationJson.string(command.get("op"),64);
                long deadline=command.containsKey("timeoutMs")?IntegrationJson.integer(command.get("timeoutMs"),1):30000;if(deadline>30000)deadline=30000;
                Thread worker=Thread.currentThread();ScheduledFuture<?> alarm=timer.schedule(worker::interrupt,deadline,TimeUnit.MILLISECONDS);boolean stop=false;
                try{
                    switch(op){
                        case "authenticate":ticket=null;AuthorizationIntegration.FreshAuthentication auth=client.authenticateFresh(username,password,optional(command,"challengeId"),optional(command,"totpCode"));result.put("ok",true);result.put("mfaRequired",auth.mfaRequired);if(auth.mfaRequired)result.put("challengeId",auth.challengeId);else ticket=auth.accessToken();break;
                        case "reconnect":client.reconnect();result.put("ok",true);break;
                        case "poll":client.poll(!Boolean.FALSE.equals(command.get("acknowledge")));result.put("ok",true);break;
                        case "check":AuthorizationIntegration.Decision decision=client.authorize(ticket,IntegrationJson.string(command.get("operation"),32),null);result.put("ok",true);result.put("isAuthorized",decision.isAuthorized);result.put("reason",decision.reason);break;
                        case "execute":String capturedTicket=ticket;String operation=IntegrationJson.string(command.get("operation"),32);int[] count={0};AuthorizationIntegration.Decision executed=client.executeProtected(ticket,operation,null,()->{client.beforeCommit(capturedTicket,operation,null);count[0]++;});result.put("ok",true);result.put("isAuthorized",executed.isAuthorized);result.put("reason",executed.reason);result.put("callbackCount",count[0]);break;
                        case "disconnect":client.disconnect();result.put("ok",true);break;
                        case "state":AuthorizationIntegration.JournalStats stats=journal.stats();result.put("ok",true);result.put("receipts",stats.receipts);result.put("effects",stats.effects);result.put("connected",stats.connected);break;
                        case "close":client.close();result.put("ok",true);stop=true;break;
                        default:result.put("reason","unsupported_command");
                    }
                }catch(Exception failure){result.put("reason",Thread.currentThread().isInterrupted()?"operation_canceled":"operation_failed");}
                finally{alarm.cancel(false);Thread.interrupted();}
                System.out.println(IntegrationJson.stringify(result));System.out.flush();if(stop)return;
            }
        }finally{timer.shutdownNow();timer.awaitTermination(5,TimeUnit.SECONDS);}
    }
    private static String optional(Map<String,Object> map,String key){return map.get(key)==null?null:IntegrationJson.string(map.get(key),512);}
}
