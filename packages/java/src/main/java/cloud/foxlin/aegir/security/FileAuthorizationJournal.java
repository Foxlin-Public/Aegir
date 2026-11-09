// Copyright Foxlin Industries. Bounded local RC1 durable journal adapter.
package cloud.foxlin.aegir.security;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

/**
 * Local journal, never an authority cache. Holds an OS-backed exclusive lock for
 * its lifetime; process death releases that lock. Same-directory forced writes
 * and atomic replacement retain complete old or new state. Checksums detect
 * corruption, not malicious host modification. Hosts must supply a private local
 * directory and retain durable receipts. Power-loss guarantees depend on the
 * filesystem; this adapter does not certify arbitrary hardware or network shares.
 */
public final class FileAuthorizationJournal implements AuthorizationIntegration.Journal {
    private final Path path;
    private final FileChannel owner;
    private final FileLock lock;
    private Map<String,Object> state;
    private boolean closed;

    public FileAuthorizationJournal(Path path) throws Exception {
        this.path=path.toAbsolutePath().normalize();Path parent=this.path.getParent();Files.createDirectories(parent);
        if(Files.isSymbolicLink(this.path)||Files.exists(this.path,LinkOption.NOFOLLOW_LINKS)&&!Files.isRegularFile(this.path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Private regular journal file required.");
        Path guard=this.path.resolveSibling(this.path.getFileName()+".lock");boolean createdGuard;
        try{Files.createFile(guard);createdGuard=true;}catch(java.nio.file.FileAlreadyExistsException existing){createdGuard=false;}
        if(Files.isSymbolicLink(guard)||!Files.isRegularFile(guard,LinkOption.NOFOLLOW_LINKS))throw new IOException("Private regular ownership guard required.");
        // No CREATE on open: a deleted/replaced guard cannot silently become a new lock.
        owner=FileChannel.open(guard,StandardOpenOption.WRITE);
        FileLock acquired;
        try{acquired=owner.tryLock();if(acquired==null)throw new IOException("Journal owned by another process.");}
        catch(Exception failure){owner.close();throw new IOException("Journal owned by another process.");}
        lock=acquired;
        try{
            if(Files.exists(this.path)){
                if(Files.size(this.path)>16777216)throw new IOException("Journal exceeds capacity.");
                Map<String,Object> envelope=IntegrationJson.object(IntegrationJson.parse(Files.readString(this.path,StandardCharsets.UTF_8)));IntegrationJson.required(envelope,"sha256","state");
                state=IntegrationJson.object(envelope.get("state"));String encoded=IntegrationJson.stringify(state);
                if(!AuthorizationIntegration.hex(MessageDigest.getInstance("SHA-256").digest(encoded.getBytes(StandardCharsets.UTF_8))).equals(envelope.get("sha256")))throw new IOException("Journal checksum mismatch.");
                validate(state);
            }else{
                if(!createdGuard)throw new IOException("Established journal missing; verified recovery required.");
                state=new LinkedHashMap<>();state.put("format",1L);state.put("binding","");state.put("connected",false);state.put("receipts",new LinkedHashMap<String,Object>());state.put("versions",new LinkedHashMap<String,Object>());state.put("effects",0L);
            }
            state.put("connected",false);persist(state);
        }catch(Exception failure){lock.release();owner.close();throw failure;}
    }
    private static void validate(Map<String,Object> s){
        IntegrationJson.required(s,"format","binding","connected","receipts","versions","effects");if(IntegrationJson.integer(s.get("format"),1)!=1)throw IntegrationJson.invalid();IntegrationJson.bool(s.get("connected"));IntegrationJson.integer(s.get("effects"),0);
        if(!(s.get("binding") instanceof String)||!((String)s.get("binding")).matches("([0-9a-f]{64})?"))throw IntegrationJson.invalid();
        Map<String,Object> receipts=IntegrationJson.object(s.get("receipts")),versions=IntegrationJson.object(s.get("versions"));
        if(receipts.size()>100000||versions.size()>10000)throw IntegrationJson.invalid();
        for(Map.Entry<String,Object> receipt:receipts.entrySet()){IntegrationJson.string(receipt.getKey(),512);if(!IntegrationJson.string(receipt.getValue(),64).matches("[0-9a-f]{64}"))throw IntegrationJson.invalid();}
        for(Map.Entry<String,Object> version:versions.entrySet()){IntegrationJson.string(version.getKey(),512);IntegrationJson.integer(version.getValue(),0);}
    }
    private Map<String,Object> copy(){
        Map<String,Object> result=new LinkedHashMap<>(state);result.put("receipts",new LinkedHashMap<>(IntegrationJson.object(state.get("receipts"))));result.put("versions",new LinkedHashMap<>(IntegrationJson.object(state.get("versions"))));return result;
    }
    private void persist(Map<String,Object> next) throws Exception {
        if(Thread.currentThread().isInterrupted())throw new IOException("Journal transaction canceled.");
        String body=IntegrationJson.stringify(next);Map<String,Object> envelope=new LinkedHashMap<>();envelope.put("sha256",AuthorizationIntegration.hex(MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8))));envelope.put("state",next);
        byte[] bytes=IntegrationJson.stringify(envelope).getBytes(StandardCharsets.UTF_8);if(bytes.length>16777216)throw new IOException("Journal capacity exceeded.");
        Path temporary=Files.createTempFile(path.getParent(),".aegir-journal-",".tmp");
        try{
            try(FileChannel file=FileChannel.open(temporary,StandardOpenOption.WRITE,StandardOpenOption.TRUNCATE_EXISTING)){ByteBuffer buffer=ByteBuffer.wrap(bytes);while(buffer.hasRemaining())file.write(buffer);file.force(true);}
            if(Thread.currentThread().isInterrupted())throw new IOException("Journal transaction canceled.");
            atomicReplaceWith(()->{if(!lock.isValid())throw new IOException("Journal ownership lost.");Files.move(temporary,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);},System.getProperty("os.name","").startsWith("Windows"),System::nanoTime,Thread::sleep);
            // Directory sync is not supported by every Windows filesystem. Do not
            // claim power-loss durability when only process-crash recovery ran.
            try(FileChannel directory=FileChannel.open(path.getParent(),StandardOpenOption.READ)){directory.force(true);}catch(IOException unsupported){/* forced file and atomic replace already completed */}
        }finally{Files.deleteIfExists(temporary);}
    }
    @FunctionalInterface interface AtomicMove {void run()throws IOException;}
    @FunctionalInterface interface RetrySleep {void sleep(long millis)throws InterruptedException;}
    // Same flushed atomic move under the existing journal monitor/owner lock.
    // No transaction replay, fallback, state advance or permission modification.
    static void atomicReplaceWith(AtomicMove move,boolean windows,java.util.function.LongSupplier now,RetrySleep sleep)throws Exception{
        long deadline=now.getAsLong()+200000000L;
        while(true){if(Thread.currentThread().isInterrupted())throw new IOException("Journal transaction canceled.");try{move.run();return;}catch(java.nio.file.AccessDeniedException denied){if(!windows||now.getAsLong()>=deadline)throw denied;long remaining=deadline-now.getAsLong();if(remaining<=0)throw denied;try{sleep.sleep(Math.max(1,Math.min(10,remaining/1000000)));}catch(InterruptedException canceled){Thread.currentThread().interrupt();throw new IOException("Journal transaction canceled.");}}}
    }
    private void active() throws IOException {if(closed)throw new IOException("Journal closed.");if(Thread.currentThread().isInterrupted())throw new IOException("Journal transaction canceled.");}
    @Override public synchronized void bind(String streamBinding) throws Exception {
        active();if(streamBinding==null||!streamBinding.matches("[0-9a-f]{64}"))throw IntegrationJson.invalid();String existing=(String)state.get("binding");
        if(!existing.isEmpty()&&!existing.equals(streamBinding))throw new IOException("Journal belongs to a different application stream.");
        if(existing.isEmpty()&&(!IntegrationJson.object(state.get("receipts")).isEmpty()||!IntegrationJson.object(state.get("versions")).isEmpty()))throw new IOException("Unbound historical journal requires operator reconciliation.");
        Map<String,Object> next=copy();next.put("binding",streamBinding);next.put("connected",false);persist(next);state=next;
    }
    @Override public synchronized AuthorizationIntegration.ApplyResult apply(List<AuthorizationIntegration.Notification> events) throws Exception {
        active();if(events==null||events.size()>100)throw new IOException("At most 100 events per transaction.");
        Map<String,Object> next=copy(),receipts=IntegrationJson.object(next.get("receipts")),versions=IntegrationJson.object(next.get("versions"));int effects=0;
        for(AuthorizationIntegration.Notification event:events){
            if(event==null||event.protocolVersion!=1||!AuthorizationIntegration.KNOWN.contains(event.eventType)||event.groupVersion<1)return new AuthorizationIntegration.ApplyResult(0,true);
            IntegrationJson.string(event.eventId,512);IntegrationJson.string(event.transactionId,512);IntegrationJson.string(event.groupId,512);if(event.userId!=null)IntegrationJson.string(event.userId,512);
            String hash=AuthorizationIntegration.hex(MessageDigest.getInstance("SHA-256").digest(IntegrationJson.stringify(event.json()).getBytes(StandardCharsets.UTF_8)));
            if(receipts.containsKey(event.eventId)){if(!hash.equals(receipts.get(event.eventId)))throw new IOException("Event identity reused with different content.");continue;}
            long prior=versions.containsKey(event.groupId)?IntegrationJson.integer(versions.get(event.groupId),0):0;
            if(event.groupVersion>prior+1)return new AuthorizationIntegration.ApplyResult(0,true);
            receipts.put(event.eventId,hash);if(event.groupVersion<prior)continue;versions.put(event.groupId,event.groupVersion);effects++;
        }
        if(receipts.size()>100000||versions.size()>10000)throw new IOException("Journal capacity exhausted; durable adapter migration required.");
        next.put("effects",IntegrationJson.integer(next.get("effects"),0)+effects);persist(next);state=next;return new AuthorizationIntegration.ApplyResult(effects,false);
    }
    @Override public synchronized void applySnapshot(AuthorizationIntegration.Snapshot snapshot) throws Exception {
        active();if(snapshot==null||snapshot.groups==null||snapshot.groups.size()>100)throw IntegrationJson.invalid();IntegrationJson.string(snapshot.snapshotId,512);
        Map<String,Object> next=copy(),versions=IntegrationJson.object(next.get("versions"));next.put("connected",false);Set<String> seen=new HashSet<>();int count=0;
        for(AuthorizationIntegration.SnapshotGroup group:snapshot.groups){
            IntegrationJson.string(group.groupId,512);long prior=versions.containsKey(group.groupId)?IntegrationJson.integer(versions.get(group.groupId),0):0;
            if(group.groupVersion<prior||group.groupVersion<0||group.subjects==null||!seen.add(group.groupId))throw new IOException("Snapshot rollback or malformed group rejected.");Set<String> subjects=new HashSet<>();
            for(AuthorizationIntegration.SnapshotSubject subject:group.subjects){if(++count>2000||subject.authorizationEpoch<0||!subjects.add(IntegrationJson.string(subject.userId,512)))throw IntegrationJson.invalid();}
            versions.put(group.groupId,group.groupVersion);
        }
        if(versions.size()>10000)throw new IOException("Journal capacity exhausted.");persist(next);state=next;
    }
    @Override public synchronized void setConnected(boolean connected) throws Exception {active();Map<String,Object> next=copy();next.put("connected",connected);persist(next);state=next;}
    @Override public synchronized AuthorizationIntegration.JournalStats stats() throws Exception {active();return new AuthorizationIntegration.JournalStats(IntegrationJson.object(state.get("receipts")).size(),Math.toIntExact(IntegrationJson.integer(state.get("effects"),0)),IntegrationJson.bool(state.get("connected")));}
    @Override public synchronized void close() throws Exception {
        if(closed)return;Exception failure=null;
        try{Map<String,Object> next=copy();next.put("connected",false);persist(next);state=next;}catch(Exception error){failure=error;}
        finally{closed=true;try{lock.release();}finally{owner.close();}}
        if(failure!=null)throw failure;
    }
}
