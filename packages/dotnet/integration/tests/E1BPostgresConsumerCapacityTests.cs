// Copyright Foxlin Industries. Real loopback PostgreSQL adversarial consumer tests, no mock authority.
using Foxlin.Aegir.Auth.AuthorizationEvents;
using Npgsql;
using Xunit;
namespace Foxlin.Aegir.Integration.Tests;
public sealed class E1BPostgresConsumerCapacityTests
{
    private static AuthorizationNotification Event(string id,long v=1)=>new(1,"tx_"+id,id,"group","subject","revoked",v);
    private sealed class Db:IAsyncDisposable
    {
        internal readonly string Root,Connection,Schema="e1b_consumer_"+Guid.NewGuid().ToString("N");
        internal Db()
        {
            Root=Environment.GetEnvironmentVariable("AEGIR_TEST_POSTGRES")??throw new InvalidOperationException("Explicit local test PostgreSQL required.");
            var b=new NpgsqlConnectionStringBuilder(Root);
            if(b.Host is not("127.0.0.1"or"localhost"or"::1")||b.Database?.Contains("test",StringComparison.OrdinalIgnoreCase)!=true)throw new InvalidOperationException("Disposable loopback test database required.");
            b.Pooling=false;b.ApplicationName="e1b_consumer";Connection=b.ConnectionString;
        }
        internal async Task Create()=>await Sql("create schema "+Schema);
        internal async Task<object?> Sql(string sql)
        {await using var c=new NpgsqlConnection(Connection);await c.OpenAsync();await using var cmd=new NpgsqlCommand(sql,c);return await cmd.ExecuteScalarAsync();}
        internal PostgresAuthorizationEventConsumerStore Store(int rows=10000,long bytes=16*1024*1024,string binding="api/org/app",AuthorizationConsumerCheckpoint? expected=null,string consumerId="consumer")=>new(Connection,Schema,consumerId,binding,rows,bytes,expected);
        public async ValueTask DisposeAsync(){/* Retain isolated synthetic state for diagnosis; no destructive cleanup. */await Task.CompletedTask;}
    }
    [Fact]
    public async Task ExplicitEstablishmentAndExistingOpenNeverAdoptMissingOrLegacyHistory()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await Assert.ThrowsAsync<PostgresException>(()=>s.InitializeAsync().AsTask());
        Assert.Equal(0L,await d.Sql($"select count(*) from information_schema.tables where table_schema='{d.Schema}'"));
        await s.EstablishAsync();await Assert.ThrowsAsync<InvalidDataException>(()=>s.EstablishAsync().AsTask());await d.Store().InitializeAsync();
        await using var legacy=new Db();await legacy.Create();await legacy.Sql($"create table {legacy.Schema}.aegir_reference_consumer_state(consumer_id text primary key,connected boolean)");
        await Assert.ThrowsAsync<InvalidDataException>(()=>legacy.Store().EstablishAsync().AsTask());
        Assert.Equal(1L,await legacy.Sql($"select count(*) from information_schema.tables where table_schema='{legacy.Schema}'"));
    }
    [Fact]
    public async Task OneSlotFullCapacityAndExactDuplicateRetainEveryReceiptEffectAndCheckpoint()
    {
        await using var d=new Db();await d.Create();var s=d.Store(rows:3);await s.EstablishAsync();
        Assert.Equal(2,(await s.ApplyAsync([Event("one"),Event("two",2)])).NewEffects);
        Assert.Equal(1,(await s.ApplyAsync([Event("three",3)])).NewEffects);var full=await s.ReadCheckpointAsync();
        Assert.Equal(0,(await s.ApplyAsync([Event("three",3)])).NewEffects);
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplyAsync([Event("four",4)]).AsTask());
        Assert.Equal(full,await s.ReadCheckpointAsync());Assert.Equal(3,await s.CountEffectsAsync());
        Assert.Equal(3L,await d.Sql($"select count(*) from {d.Schema}.aegir_reference_receipts"));
    }
    [Theory]
    [InlineData("transaction")][InlineData("group")][InlineData("user")][InlineData("type")][InlineData("version")]
    public async Task ReusedEventIdentityRejectsEveryChangedAuthorityField(string field)
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();var e=Event("same");await s.ApplyAsync([e]);var before=await s.ReadCheckpointAsync();
        var changed=field switch{"transaction"=>e with{TransactionId="other"},"group"=>e with{GroupId="other"},"user"=>e with{UserId=null},"type"=>e with{EventType="granted"},_=>e with{GroupVersion=2}};
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplyAsync([changed]).AsTask());Assert.Equal(before,await s.ReadCheckpointAsync());Assert.Equal(1,await s.CountEffectsAsync());
        Assert.True((await s.ApplyAsync([e with{ProtocolVersion=2}])).RequiresSnapshot);Assert.Equal(before,await s.ReadCheckpointAsync());
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task ExactByteBoundaryRefusesGrowthButAllowsIdempotentDuplicate(bool escaped)
    {
        string binding=escaped?new string('"',200)+"\\nonASCII_\u00e9":"api/org/app",id=escaped?new string('"',100)+"\\":"consumer";
        var item=Event("byte_"+new string('x',80)); // Keep the measured exact boundary above the minimum supported1024-byte policy.
        await using var measured=new Db();await measured.Create();var m=measured.Store(binding:binding,consumerId:id);await m.EstablishAsync();await m.ApplyAsync([item]);
        long bytes=Convert.ToInt64(await measured.Sql($"select octet_length((to_jsonb(s)-'connected')::text)+1 from {measured.Schema}.aegir_reference_consumer_state s"));
        foreach(string table in new[]{"receipts","versions","effects","snapshot_subjects","snapshots","snapshot_groups","subject_epochs","checkpoints"})
            bytes+=Convert.ToInt64(await measured.Sql($"select coalesce(sum(octet_length(row_to_json(r)::text)+1),0)::bigint from {measured.Schema}.aegir_reference_{table} r"));
        // Independent SQL accounting; adjust only the decimal max_bytes field's own serialized length.
        long measuredBytes=bytes;for(int i=0;i<5;i++)bytes=measuredBytes+bytes.ToString(System.Globalization.CultureInfo.InvariantCulture).Length-(16*1024*1024).ToString().Length;
        await using var d=new Db();await d.Create();var s=d.Store(bytes:bytes,binding:binding,consumerId:id);await s.EstablishAsync();Assert.Equal(1,(await s.ApplyAsync([item])).NewEffects);
        var before=await s.ReadCheckpointAsync();Assert.Equal(0,(await s.ApplyAsync([item])).NewEffects);
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplyAsync([Event("overflow",2)]).AsTask());Assert.Equal(before,await s.ReadCheckpointAsync());
    }
    [Fact]
    public async Task HigherGroupVersionCannotRollBackRetainedSubjectEpochAfterInvalidationOrAbsence()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();
        await s.ApplySnapshotAsync(new("epoch_baseline",[new("group",4,[new("subject",true,9)])]));
        await s.ApplyAsync([Event("invalidate",5)]);await s.ApplySnapshotAsync(new("absent",[]));var before=await s.ReadCheckpointAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplySnapshotAsync(new("rollback",[new("group",6,[new("subject",true,8)])])).AsTask());
        Assert.Equal(before,await s.ReadCheckpointAsync());Assert.Equal(9L,await d.Sql($"select authorization_epoch from {d.Schema}.aegir_reference_subject_epochs"));
    }
    [Theory]
    [InlineData("binding")][InlineData("policy")]
    public async Task CorruptHeadCannotRebindStreamOrReplaceEstablishedCapacityPolicy(string field)
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();await s.ApplyAsync([Event("bound")]);
        await d.Sql($"update {d.Schema}.aegir_reference_consumer_state set "+(field=="binding"?"binding='other'":"max_rows=999"));
        var changed=field=="binding"?d.Store(binding:"other"):d.Store(rows:999);
        await Assert.ThrowsAsync<InvalidDataException>(()=>changed.InitializeAsync().AsTask());
    }
    [Fact]
    public async Task SnapshotRollbackConflictsAndAbsentGroupWatermarksRemainDenied()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();
        var snapshot=new AuthorizationConsumerSnapshot("snapshot",[new("group",4,[new("subject",true,9)])]);await s.ApplySnapshotAsync(snapshot);var before=await s.ReadCheckpointAsync();
        await s.ApplySnapshotAsync(snapshot);Assert.Equal(before,await s.ReadCheckpointAsync());
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplySnapshotAsync(new("older",[new("group",3,[])])).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplySnapshotAsync(new("conflict",[new("group",4,[new("subject",false,8)])])).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplySnapshotAsync(new("snapshot",[new("group",5,[])])).AsTask());
        await s.ApplySnapshotAsync(new("absent",[]));await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplySnapshotAsync(new("reintroduced",[new("group",1,[])])).AsTask());
        Assert.Equal(4L,await d.Sql($"select version from {d.Schema}.aegir_reference_versions where group_id='group'"));
        await Assert.ThrowsAsync<InvalidDataException>(()=>d.Store(binding:"other-stream").InitializeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>d.Store(rows:999).InitializeAsync().AsTask());
    }
    [Theory]
    [InlineData("receipts")][InlineData("effects")][InlineData("checkpoints")][InlineData("consumer_state")]
    public async Task SelectivelyMissingEstablishedHistoryFailsClosedWithoutReinitializing(string table)
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();var e=Event("retained");await s.ApplyAsync([e]);
        await d.Sql($"delete from {d.Schema}.aegir_reference_{table}");
        await Assert.ThrowsAsync<InvalidDataException>(()=>d.Store().InitializeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplyAsync([e]).AsTask());
        Assert.Equal(0L,await d.Sql($"select count(*) from {d.Schema}.aegir_reference_{table}"));
    }
    [Fact]
    public async Task CorruptedFingerprintAndMissingTableAreNotHealedByDuplicateOrOpen()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();await s.ApplyAsync([Event("retained")]);
        await d.Sql($"update {d.Schema}.aegir_reference_receipts set fingerprint=repeat('0',64)");
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.ApplyAsync([Event("retained")]).AsTask());
        await d.Sql($"alter table {d.Schema}.aegir_reference_effects rename to retained_missing_effects");
        await Assert.ThrowsAsync<PostgresException>(()=>s.InitializeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>s.EstablishAsync().AsTask());
    }
    [Fact]
    public async Task GapOrMalformedBatchCannotPartiallyCommitEarlierValidEntries()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();var before=await s.ReadCheckpointAsync();
        Assert.True((await s.ApplyAsync([Event("first"),Event("gap",4)])).RequiresSnapshot);Assert.Equal(before,await s.ReadCheckpointAsync());
        Assert.True((await s.ApplyAsync([Event("first"),Event("invalid")with{GroupId="\n"}])).RequiresSnapshot);Assert.Equal(before,await s.ReadCheckpointAsync());Assert.Equal(0,await s.CountEffectsAsync());
    }
    [Fact]
    public async Task DeterministicConcurrentSubscriberBarrierCannotOvercommitOneRemainingSlot()
    {
        await using var d=new Db();await d.Create();var s=d.Store(rows:3);await s.EstablishAsync();await s.ApplyAsync([Event("one"),Event("two",2)]);
        await using var gate=new NpgsqlConnection(d.Connection);await gate.OpenAsync();await using var tx=await gate.BeginTransactionAsync();
        await using(var held=new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended(@b,20261016003))",gate,tx)){held.Parameters.AddWithValue("b",'"'+d.Schema+'"'+":consumer");await held.ExecuteNonQueryAsync();}
        async Task<bool> Try(string id){try{await d.Store(rows:3).ApplyAsync([Event(id,3)]);return true;}catch(InvalidDataException){return false;}}
        var a=Try("parallel_a");var b=Try("parallel_b");var timer=System.Diagnostics.Stopwatch.StartNew();
        while(Convert.ToInt64(await d.Sql("select count(*) from pg_stat_activity where datname=current_database() and application_name='e1b_consumer' and wait_event_type='Lock'"))<2)
        {Assert.True(timer.Elapsed<TimeSpan.FromSeconds(15),"Both actual PostgreSQL advisory waits must be observed.");await Task.Delay(10);}
        await tx.CommitAsync();var results=await Task.WhenAll(a,b);Assert.Single(results,x=>x);Assert.Equal(3,await s.CountEffectsAsync());
    }
    [Fact]
    public async Task RestartUsesIndependentMinimumCheckpointAndRejectsMissingOrWrongWitness()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();await s.ApplyAsync([Event("one")]);var proof=await s.ReadCheckpointAsync();
        var reopened=d.Store(expected:proof);await reopened.InitializeAsync();Assert.Equal(0,(await reopened.ApplyAsync([Event("one")])).NewEffects);
        await Assert.ThrowsAsync<InvalidDataException>(()=>d.Store(expected:proof with{Revision=proof.Revision+1}).InitializeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>d.Store(expected:proof with{StateHash=new string('0',64)}).InitializeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>reopened.EstablishAsync().AsTask());
    }
    [Fact]
    public async Task IndependentPhysicalDatabaseCopyRejectsOldRestorationAndAcceptsCurrentRetainedProof()
    {
        await using var d=new Db();await d.Create();var s=d.Store();await s.EstablishAsync();await s.ApplyAsync([Event("one")]);
        var builder=new NpgsqlConnectionStringBuilder(d.Connection);string source=builder.Database!;builder.Database="postgres";
        async Task<string> Copy()
        {
            string name="e1b_physical_restore_test_"+Guid.NewGuid().ToString("N");
            await using var admin=new NpgsqlConnection(builder.ConnectionString);await admin.OpenAsync();
            await using var cmd=new NpgsqlCommand($"create database \"{name}\" template \"{source}\"",admin);await cmd.ExecuteNonQueryAsync();
            return new NpgsqlConnectionStringBuilder(d.Connection){Database=name}.ConnectionString;
        }
        string oldCopy=await Copy();await s.ApplyAsync([Event("two",2)]);var independentlyRetained=await s.ReadCheckpointAsync();
        var old=new PostgresAuthorizationEventConsumerStore(oldCopy,d.Schema,"consumer","api/org/app",expectedCheckpoint:independentlyRetained);
        await Assert.ThrowsAsync<InvalidDataException>(()=>old.InitializeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(()=>old.ApplyAsync([Event("two",2)]).AsTask());
        string currentCopy=await Copy();var restored=new PostgresAuthorizationEventConsumerStore(currentCopy,d.Schema,"consumer","api/org/app",expectedCheckpoint:independentlyRetained);
        await restored.InitializeAsync();Assert.Equal(independentlyRetained,await restored.ReadCheckpointAsync());
        Assert.Equal(0,(await restored.ApplyAsync([Event("two",2)])).NewEffects);Assert.Equal(2,await restored.CountEffectsAsync());Assert.Equal(2,await s.CountEffectsAsync());
    }
}
