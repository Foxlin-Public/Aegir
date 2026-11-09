// Copyright Foxlin Industries. Consumer-owned invalidation journal; never an authority engine.
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
namespace Foxlin.Aegir.Auth.AuthorizationEvents;

/// <summary>Nonsecret minimum continuity receipt. Retain outside the database rollback domain before ACK.</summary>
public sealed record AuthorizationConsumerCheckpoint(string ScopeBinding, long Revision, string StateHash);

/// <summary>Atomic bounded journal. Explicit fresh establishment; normal initialization never creates history.
/// SQL integrity detects selective damage; independently retained receipts are required to detect coherent restoration rollback.</summary>
public sealed class PostgresAuthorizationEventConsumerStore : IAuthorizationEventConsumerStore
{
    /// <summary>Upper row bound per retained history table.</summary>
    public const int MaximumRetainedHistory = 10000;
    /// <summary>Canonical UTF-8 retained-byte ceiling; PostgreSQL disk/WAL/index overhead is separate.</summary>
    public const long MaximumRetainedBytes = 16 * 1024 * 1024;
    private readonly string _connectionString, _schema, _id, _binding;
    private readonly int _rows;
    private readonly long _bytes;
    private readonly AuthorizationConsumerCheckpoint? _expected;
    private static readonly string[] Tables = ["receipts", "versions", "effects", "snapshot_subjects", "snapshots", "snapshot_groups", "subject_epochs"];
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    { "granted", "revoked", "adminGranted", "adminRevoked", "permissionChanged", "licenseGranted", "licenseRevoked", "membershipChanged", "suspended", "restored", "groupPolicyChanged" };
    /// <summary>consumerId must identify a stable API/organization/application stream.</summary>
    public PostgresAuthorizationEventConsumerStore(string connectionString,string existingSchema,string consumerId)
        :this(connectionString,existingSchema,consumerId,consumerId) { }
    /// <summary>Binding and capacity policy cannot change after establishment. Lower test/deployment limits are supported.</summary>
    public PostgresAuthorizationEventConsumerStore(string connectionString,string existingSchema,string consumerId,string scopeBinding,
        int maximumRetainedHistory=MaximumRetainedHistory,long maximumRetainedBytes=MaximumRetainedBytes,AuthorizationConsumerCheckpoint? expectedCheckpoint=null)
    {
        if(string.IsNullOrWhiteSpace(connectionString)||string.IsNullOrWhiteSpace(existingSchema)||existingSchema.Length>63||existingSchema.Any(x=>!(char.IsAsciiLetterOrDigit(x)||x=='_'))||!Id(consumerId)||consumerId.Length>128||!Id(scopeBinding))throw new ArgumentException("Bounded consumer database/schema/stream identity required.");
        if(maximumRetainedHistory is <1 or >MaximumRetainedHistory||maximumRetainedBytes is <1024 or >MaximumRetainedBytes)throw new ArgumentException("Invalid retained-history policy.");
        if(expectedCheckpoint is not null&&(expectedCheckpoint.ScopeBinding!=scopeBinding||expectedCheckpoint.Revision<0||!Hash(expectedCheckpoint.StateHash)))throw new ArgumentException("Invalid independent receipt.");
        _connectionString=connectionString;_schema='"'+existingSchema+'"';_id=consumerId;_binding=scopeBinding;_rows=maximumRetainedHistory;_bytes=maximumRetainedBytes;_expected=expectedCheckpoint;
    }
    /// <summary>Explicit first installation only. Never use to repair missing, legacy or restored state.</summary>
    public async ValueTask EstablishAsync(CancellationToken ct=default)
    {
        if(_expected is not null)throw new InvalidDataException("Independent receipt forbids fresh establishment.");
        await using var c=await Open(ct);await using var t=await c.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);
        await Exec(c,t,"select pg_advisory_xact_lock(hashtextextended(@s,20261028001))",ct,("s",_schema));await Lock(c,t,ct);
        string[] names=["consumer_state",..Tables,"checkpoints"];int present=0;
        foreach(string name in names)if((bool)(await Scalar(c,t,"select to_regclass(@n) is not null",ct,("n",_schema+".aegir_reference_"+name)))!)present++;
        if(present!=0&&present!=names.Length)throw new InvalidDataException("Incomplete or legacy journal requires reconciliation.");
        if(present==0)await Exec(c,t,$"""
            create table {_schema}.aegir_reference_consumer_state(consumer_id text primary key,binding text not null,format_version int not null,revision bigint not null,state_hash text not null,max_rows int not null,max_bytes bigint not null,connected boolean not null);
            create table {_schema}.aegir_reference_receipts(consumer_id text not null,event_id text not null,transaction_id text not null,group_id text not null,group_version bigint not null,fingerprint text not null,primary key(consumer_id,event_id));
            create table {_schema}.aegir_reference_versions(consumer_id text not null,group_id text not null,version bigint not null,primary key(consumer_id,group_id));
            create table {_schema}.aegir_reference_effects(consumer_id text not null,event_id text not null,event_type text not null,primary key(consumer_id,event_id));
            create table {_schema}.aegir_reference_snapshot_subjects(consumer_id text not null,group_id text not null,user_id text not null,authorization_epoch bigint not null,primary key(consumer_id,group_id,user_id));
            create table {_schema}.aegir_reference_snapshots(consumer_id text not null,snapshot_id text not null,fingerprint text not null,primary key(consumer_id,snapshot_id));
            create table {_schema}.aegir_reference_snapshot_groups(consumer_id text not null,group_id text not null,version bigint not null,fingerprint text not null,primary key(consumer_id,group_id));
            create table {_schema}.aegir_reference_subject_epochs(consumer_id text not null,group_id text not null,user_id text not null,authorization_epoch bigint not null,primary key(consumer_id,group_id,user_id));
            create table {_schema}.aegir_reference_checkpoints(consumer_id text not null,revision bigint not null,state_hash text not null,previous_hash text not null,primary key(consumer_id,revision));
            """,ct);
        foreach(string name in names)if((bool)(await Scalar(c,t,$"select exists(select 1 from {_schema}.aegir_reference_{name} where consumer_id=@consumer)",ct))!)throw new InvalidDataException("Retained consumer state/history forbids establishment.");
        string root=await StateHash(c,t,ct);
        await Exec(c,t,$"insert into {_schema}.aegir_reference_consumer_state values(@consumer,@b,2,0,@h,@r,@bytes,false)",ct,("b",_binding),("h",root),("r",_rows),("bytes",_bytes));
        await Checkpoint(c,t,0,root,"",ct);await Validate(c,t,ct);await t.CommitAsync(ct);
    }
    /// <summary>Open established format2 state, validate continuity and start disconnected; no automatic DDL or adoption.</summary>
    public async ValueTask InitializeAsync(CancellationToken ct=default)=>await SetConnectedAsync(false,ct);
    /// <inheritdoc />
    public async ValueTask<AuthorizationConsumerApplyResult> ApplyAsync(IReadOnlyList<AuthorizationNotification> events,CancellationToken ct=default)
    {
        if(events is null||events.Count>100)throw new ArgumentException("Bounded events required.");
        await using var c=await Open(ct);await using var t=await c.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);await Lock(c,t,ct);var before=await Validate(c,t,ct);int effects=0;bool changed=false;
        foreach(var e in events)
        {
            if(e is null||e.ProtocolVersion!=1||!Known.Contains(e.EventType)||e.GroupVersion<1||!Id(e.EventId)||!Id(e.TransactionId)||!Id(e.GroupId)||e.UserId is not null&&!Id(e.UserId))return new(0,true);
            string hash=Digest(JsonSerializer.SerializeToUtf8Bytes(e,FileConsumerJsonContext.Default.AuthorizationNotification));
            object? seen=await Scalar(c,t,$"select fingerprint from {_schema}.aegir_reference_receipts where consumer_id=@consumer and event_id=@e",ct,("e",e.EventId));
            if(seen is not null){if(!Equals(seen,hash))throw new InvalidDataException("Conflicting event identity.");continue;}
            long prior=await Version(c,t,e.GroupId,ct)??0;
            if(e.GroupVersion>prior&&e.GroupVersion-prior>1)return new(0,true);
            await Exec(c,t,$"insert into {_schema}.aegir_reference_receipts values(@consumer,@e,@tx,@g,@v,@h)",ct,("e",e.EventId),("tx",e.TransactionId),("g",e.GroupId),("v",e.GroupVersion),("h",hash));changed=true;
            if(e.GroupVersion<prior)continue;
            await PutVersion(c,t,e.GroupId,e.GroupVersion,ct);
            await Exec(c,t,$"insert into {_schema}.aegir_reference_effects values(@consumer,@e,@type)",ct,("e",e.EventId),("type",e.EventType));
            await Exec(c,t,$"delete from {_schema}.aegir_reference_snapshot_subjects where consumer_id=@consumer and group_id=@g",ct,("g",e.GroupId));effects++;
        }
        if(changed)await Advance(c,t,before,ct);await t.CommitAsync(ct);return new(effects,false);
    }
    /// <inheritdoc />
    public async ValueTask ApplySnapshotAsync(AuthorizationConsumerSnapshot snapshot,CancellationToken ct=default)
    {
        if(snapshot is null||!Id(snapshot.SnapshotId)||snapshot.Groups is null||snapshot.Groups.Count>100||snapshot.Groups.Any(x=>x is null||x.Subjects is null)||snapshot.Groups.Sum(x=>x.Subjects.Count)>2000)throw new ArgumentException("Bounded snapshot required.");
        if(snapshot.Groups.Select(x=>x.GroupId).Distinct(StringComparer.Ordinal).Count()!=snapshot.Groups.Count)throw new InvalidDataException("Duplicate snapshot group.");
        await using var c=await Open(ct);await using var t=await c.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);await Lock(c,t,ct);var before=await Validate(c,t,ct);
        foreach(var g in snapshot.Groups)
        {
            if(!Id(g.GroupId)||g.GroupVersion<0||g.Subjects.Any(x=>x is null||!Id(x.UserId)||x.AuthorizationEpoch<0)||g.Subjects.Select(x=>x.UserId).Distinct(StringComparer.Ordinal).Count()!=g.Subjects.Count)throw new InvalidDataException("Invalid snapshot group.");
            if(g.GroupVersion<(await Version(c,t,g.GroupId,ct)??0))throw new InvalidDataException("Snapshot rollback requires reconciliation.");
            foreach(var subject in g.Subjects)
            {
                object? epoch=await Scalar(c,t,$"select authorization_epoch from {_schema}.aegir_reference_subject_epochs where consumer_id=@consumer and group_id=@g and user_id=@u",ct,("g",g.GroupId),("u",subject.UserId));
                if(epoch is not null&&subject.AuthorizationEpoch<Convert.ToInt64(epoch))throw new InvalidDataException("Snapshot subject epoch rollback requires reconciliation.");
            }
            object? old=await Scalar(c,t,$"select fingerprint from {_schema}.aegir_reference_snapshot_groups where consumer_id=@consumer and group_id=@g and version=@v",ct,("g",g.GroupId),("v",g.GroupVersion));
            if(old is not null&&!Equals(old,GroupHash(g)))throw new InvalidDataException("Conflicting snapshot group version.");
        }
        string hash=Digest(JsonSerializer.SerializeToUtf8Bytes(snapshot,AuthorizationConsumerJsonContext.Default.AuthorizationConsumerSnapshot));
        object? receipt=await Scalar(c,t,$"select fingerprint from {_schema}.aegir_reference_snapshots where consumer_id=@consumer and snapshot_id=@s",ct,("s",snapshot.SnapshotId));
        if(receipt is not null){if(!Equals(receipt,hash))throw new InvalidDataException("Conflicting snapshot identity.");await t.CommitAsync(ct);return;}
        await Exec(c,t,$"insert into {_schema}.aegir_reference_snapshots values(@consumer,@s,@h)",ct,("s",snapshot.SnapshotId),("h",hash));
        // Disposable reconciled view only. High-watermarks and all receipt/checkpoint identities survive.
        await Exec(c,t,$"delete from {_schema}.aegir_reference_snapshot_subjects where consumer_id=@consumer",ct);
        foreach(var g in snapshot.Groups)
        {
            await PutVersion(c,t,g.GroupId,g.GroupVersion,ct);
            await Exec(c,t,$"insert into {_schema}.aegir_reference_snapshot_groups values(@consumer,@g,@v,@h) on conflict(consumer_id,group_id) do update set version=excluded.version,fingerprint=excluded.fingerprint",ct,("g",g.GroupId),("v",g.GroupVersion),("h",GroupHash(g)));
            foreach(var subject in g.Subjects)await Exec(c,t,$"insert into {_schema}.aegir_reference_subject_epochs values(@consumer,@g,@u,@epoch) on conflict(consumer_id,group_id,user_id) do update set authorization_epoch=greatest(aegir_reference_subject_epochs.authorization_epoch,excluded.authorization_epoch)",ct,("g",g.GroupId),("u",subject.UserId),("epoch",subject.AuthorizationEpoch));
            foreach(var s in g.Subjects.Where(x=>x.Allowed))await Exec(c,t,$"insert into {_schema}.aegir_reference_snapshot_subjects values(@consumer,@g,@u,@epoch)",ct,("g",g.GroupId),("u",s.UserId),("epoch",s.AuthorizationEpoch));
        }
        await Advance(c,t,before,ct);await t.CommitAsync(ct);
    }
    /// <inheritdoc />
    public async ValueTask SetConnectedAsync(bool connected,CancellationToken ct=default)
    {
        await using var c=await Open(ct);await using var t=await c.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);await Lock(c,t,ct);await Validate(c,t,ct);
        await Exec(c,t,$"update {_schema}.aegir_reference_consumer_state set connected=@c where consumer_id=@consumer",ct,("c",connected));await t.CommitAsync(ct);
    }
    /// <summary>Caller retains receipt independently before acknowledging covered work. Never persist credentials in it.</summary>
    public async ValueTask<AuthorizationConsumerCheckpoint> ReadCheckpointAsync(CancellationToken ct=default)
    {
        await using var c=await Open(ct);await using var t=await c.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);await Lock(c,t,ct);var head=await Validate(c,t,ct);await t.CommitAsync(ct);return head;
    }
    /// <summary>Validated committed invalidation count; no credential or identity detail returned.</summary>
    public async ValueTask<int> CountEffectsAsync(CancellationToken ct=default)
    {
        await using var c=await Open(ct);await using var t=await c.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);await Lock(c,t,ct);await Validate(c,t,ct);
        return Convert.ToInt32(await Scalar(c,t,$"select count(*) from {_schema}.aegir_reference_effects where consumer_id=@consumer",ct));
    }
    private async ValueTask<AuthorizationConsumerCheckpoint> Validate(NpgsqlConnection c,NpgsqlTransaction t,CancellationToken ct)
    {
        long revision;string root;
        await using(var cmd=Command(c,t,$"select binding,format_version,revision,state_hash,max_rows,max_bytes from {_schema}.aegir_reference_consumer_state where consumer_id=@consumer"))
        await using(var reader=await cmd.ExecuteReaderAsync(ct))
        {
            if(!await reader.ReadAsync(ct)||reader.GetString(0)!=_binding||reader.GetInt32(1)!=2||reader.GetInt32(4)!=_rows||reader.GetInt64(5)!=_bytes)throw new InvalidDataException("Established binding/policy unavailable; operator reconciliation required.");
            revision=reader.GetInt64(2);root=reader.GetString(3);
        }
        if(revision<0||!Hash(root)||root!=await StateHash(c,t,ct))throw new InvalidDataException("Consumer history continuity unavailable.");
        await using(var cmd=Command(c,t,$"select revision,state_hash,previous_hash from {_schema}.aegir_reference_checkpoints where consumer_id=@consumer order by revision limit {_rows+1}"))
        await using(var reader=await cmd.ExecuteReaderAsync(ct))
        {
            long next=0;string prior="";bool matched=_expected is null;
            while(await reader.ReadAsync(ct))
            {
                if(next>=_rows||reader.GetInt64(0)!=next||!Hash(reader.GetString(1))||reader.GetString(2)!=prior)throw new InvalidDataException("Checkpoint continuity unavailable.");
                prior=reader.GetString(1);if(_expected is not null&&next==_expected.Revision)matched=prior==_expected.StateHash;next++;
            }
            if(next!=revision+1||prior!=root||!matched)throw new InvalidDataException("Retained independent checkpoint/history missing.");
        }
        await Budget(c,t,ct);return new(_binding,revision,root);
    }
    private async ValueTask Advance(NpgsqlConnection c,NpgsqlTransaction t,AuthorizationConsumerCheckpoint prior,CancellationToken ct)
    {
        string hash=await StateHash(c,t,ct);long revision=checked(prior.Revision+1);
        await Checkpoint(c,t,revision,hash,prior.StateHash,ct);
        await Exec(c,t,$"update {_schema}.aegir_reference_consumer_state set revision=@v,state_hash=@h where consumer_id=@consumer",ct,("v",revision),("h",hash));await Budget(c,t,ct);
    }
    private ValueTask Checkpoint(NpgsqlConnection c,NpgsqlTransaction t,long revision,string hash,string previous,CancellationToken ct)=>Exec(c,t,$"insert into {_schema}.aegir_reference_checkpoints values(@consumer,@v,@h,@p)",ct,("v",revision),("h",hash),("p",previous));
    private async ValueTask<string> StateHash(NpgsqlConnection c,NpgsqlTransaction t,CancellationToken ct)
    {
        using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData(Encoding.UTF8.GetBytes("v2\n"+Encoding.UTF8.GetByteCount(_binding).ToString(System.Globalization.CultureInfo.InvariantCulture)+":"+_binding+"\n"+_id+"\n"+_rows.ToString(System.Globalization.CultureInfo.InvariantCulture)+"\n"+_bytes.ToString(System.Globalization.CultureInfo.InvariantCulture)+"\n"));
        foreach(string name in Tables)
        {
            digest.AppendData(Encoding.UTF8.GetBytes(name+"\n"));int limit=name=="snapshot_subjects"?2000:_rows;
            string order=name is "snapshot_subjects" or "subject_epochs"?"1,2,3":"1,2";
            await using var cmd=Command(c,t,$"select row_to_json(r)::text from (select * from {_schema}.aegir_reference_{name} where consumer_id=@consumer order by {order} limit {limit+1}) r");
            await using var reader=await cmd.ExecuteReaderAsync(ct);int count=0;
            while(await reader.ReadAsync(ct)){if(++count>limit)throw new InvalidDataException("Retained row capacity exhausted.");digest.AppendData(Encoding.UTF8.GetBytes(reader.GetString(0)+"\n"));}
        }
        return Convert.ToHexString(digest.GetHashAndReset());
    }
    private async ValueTask Budget(NpgsqlConnection c,NpgsqlTransaction t,CancellationToken ct)
    {
        // Exact canonical UTF-8 security head bytes. Connection status is not retained authority and is excluded.
        object? state=await Scalar(c,t,$"select (to_jsonb(s)-'connected')::text from {_schema}.aegir_reference_consumer_state s where consumer_id=@consumer",ct);
        if(state is not string head)throw new InvalidDataException("Established security head missing.");
        long bytes=Encoding.UTF8.GetByteCount(head)+1;
        foreach(string name in Tables.Append("checkpoints"))
        {
            int limit=name=="snapshot_subjects"?2000:_rows;await using var cmd=Command(c,t,$"select row_to_json(r)::text from (select * from {_schema}.aegir_reference_{name} where consumer_id=@consumer limit {limit+1}) r");
            await using var reader=await cmd.ExecuteReaderAsync(ct);int count=0;
            while(await reader.ReadAsync(ct)){bytes=checked(bytes+Encoding.UTF8.GetByteCount(reader.GetString(0))+1);if(++count>limit||bytes>_bytes)throw new InvalidDataException("History capacity requires reconciliation; no immutable records evicted.");}
        }
    }
    private async ValueTask<long?> Version(NpgsqlConnection c,NpgsqlTransaction t,string group,CancellationToken ct)
    {object? value=await Scalar(c,t,$"select version from {_schema}.aegir_reference_versions where consumer_id=@consumer and group_id=@g",ct,("g",group));return value is null?null:Convert.ToInt64(value);}
    private ValueTask PutVersion(NpgsqlConnection c,NpgsqlTransaction t,string group,long version,CancellationToken ct)=>Exec(c,t,$"insert into {_schema}.aegir_reference_versions values(@consumer,@g,@v) on conflict(consumer_id,group_id) do update set version=greatest(aegir_reference_versions.version,excluded.version)",ct,("g",group),("v",version));
    private static string GroupHash(AuthorizationConsumerGroup group)=>Digest(JsonSerializer.SerializeToUtf8Bytes(new AuthorizationConsumerSnapshot("group",[group with{Subjects=group.Subjects.OrderBy(x=>x.UserId,StringComparer.Ordinal).ToArray()}]),AuthorizationConsumerJsonContext.Default.AuthorizationConsumerSnapshot));
    private static bool Id(string? v)=>!string.IsNullOrWhiteSpace(v)&&v.Length<=256&&!v.Any(char.IsControl)&&Encoding.UTF8.GetByteCount(v)<=1024;
    private static bool Hash(string v)=>v.Length==64&&v.All(Uri.IsHexDigit);
    private static string Digest(byte[] b)=>Convert.ToHexString(SHA256.HashData(b));
    private async ValueTask<NpgsqlConnection> Open(CancellationToken ct){var c=new NpgsqlConnection(_connectionString);try{await c.OpenAsync(ct);return c;}catch{await c.DisposeAsync();throw;}}
    private ValueTask Lock(NpgsqlConnection c,NpgsqlTransaction t,CancellationToken ct)=>Exec(c,t,"select pg_advisory_xact_lock(hashtextextended(@b,20261016003))",ct,("b",_schema+":"+_id));
    private async ValueTask Exec(NpgsqlConnection c,NpgsqlTransaction t,string sql,CancellationToken ct,params(string,object)[] values){await using var cmd=Command(c,t,sql,values);await cmd.ExecuteNonQueryAsync(ct);}
    private async ValueTask<object?> Scalar(NpgsqlConnection c,NpgsqlTransaction t,string sql,CancellationToken ct,params(string,object)[] values){await using var cmd=Command(c,t,sql,values);return await cmd.ExecuteScalarAsync(ct);}
    private NpgsqlCommand Command(NpgsqlConnection c,NpgsqlTransaction t,string sql,params(string,object)[] values){var cmd=new NpgsqlCommand(sql,c,t);cmd.Parameters.AddWithValue("consumer",_id);foreach(var(name,value)in values)cmd.Parameters.AddWithValue(name,value);return cmd;}
}
