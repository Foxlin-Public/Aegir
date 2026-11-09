// Copyright Foxlin Industries. Configuration is a private local file, never command-line secrets.
using System.Text.Json;
using Foxlin.Aegir.Auth.AuthorizationEvents;

if (args.Length == 2 && args[0] == "--availability")
{
    using var settingsDocument = JsonDocument.Parse(File.ReadAllText(args[1]));
    var settings = settingsDocument.RootElement;
    string Get(string name) => settings.GetProperty(name).GetString()!;
    using var availabilityJournal = new FileAuthorizationEventConsumerStore(Get("journalPath"), Get("apiBaseUrl") + "|" + Get("organizationId") + "|" + Get("applicationId"));
    using var integration = new AegirIntegrationClient(new(new(Get("apiBaseUrl")), new(Get("webBaseUrl")), Get("organizationId"), Get("applicationId"), Get("applicationCredential"), Get("certificateSha256")), availabilityJournal);
    var login = await integration.AuthenticateAsync(Get("username"), Get("password"));
    if (!login.Authenticated) return 3;
    await integration.Events.ReconnectAsync();
    var measurements = new List<object>();
    foreach (string mode in new[] { "periodic-reconnect", "healthy-poll" })
    {
        for (int run = 0; run < 3; run++)
        {
            int denied = 0, allowed = 0;
            var samples = new List<double>();
            var poll = Task.Run(async () =>
            {
                for (int i = 0; i < 4; i++)
                {
                    if (mode == "periodic-reconnect") await integration.Events.ReconnectAsync();
                    else await integration.Events.PollAsync();
                    await Task.Delay(300);
                }
            });
            for (int i = 0; i < 100; i++)
            {
                var timer = System.Diagnostics.Stopwatch.StartNew();
                var decision = await integration.AuthorizeAsync("read");
                samples.Add(timer.Elapsed.TotalMilliseconds);
                if (decision.IsAuthorized) allowed++; else denied++;
                await Task.Delay(10);
            }
            await poll;
            samples.Sort();
            measurements.Add(new { mode, run, checks = 100, allowed, denied, medianMs = samples[50], p95Ms = samples[95] });
        }
    }
    Console.WriteLine(JsonSerializer.Serialize(new { status = "PASS", measurements, topology = "Actual pinned HTTPS Kestrel and isolated PostgreSQL; same current canonical check in both modes", limitation = "Laptop-only synthetic n=3 runs/mode,100 checks/run; periodic reconnect comparator uses the conservative previous lifecycle, not an old source binary" }));
    return 0;
}

if (args.Length != 1) return 2;
using JsonDocument config = JsonDocument.Parse(File.ReadAllText(args[0]));
var c = config.RootElement;
string Setting(string name) => c.GetProperty(name).GetString()!;
using var journal = new FileAuthorizationEventConsumerStore(Setting("journalPath"), Setting("apiBaseUrl") + "|" + Setting("organizationId") + "|" + Setting("applicationId"));
using var client = new AegirIntegrationClient(new(new(Setting("apiBaseUrl")), new(Setting("webBaseUrl")),
    Setting("organizationId"), Setting("applicationId"), Setting("applicationCredential"), Setting("certificateSha256")), journal);
while (Console.ReadLine() is string line)
{
    string? requestId = null;
    try
    {
        using var command = JsonDocument.Parse(line);
        var p = command.RootElement;
        requestId = p.TryGetProperty("requestId", out var rid) ? rid.ToString() : null;
        string op = p.GetProperty("op").GetString()!;
        string operation = p.TryGetProperty("operation", out var operationValue) ? operationValue.GetString()! : "read";
        object result;
        int timeoutMs = p.TryGetProperty("timeoutMs", out var timeout) ? Math.Clamp(timeout.GetInt32(), 1, 30000) : 25000;
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeoutMs));
        switch (op)
        {
            case "authenticate":
                var auth = await client.AuthenticateAsync(Setting("username"), Setting("password"),
                    p.TryGetProperty("challengeId", out var challenge) ? challenge.GetString() : null,
                    p.TryGetProperty("totpCode", out var totp) ? totp.GetString() : null, deadline.Token);
                result = new { authenticated = auth.Authenticated, mfaRequired = auth.MfaRequired, auth.ChallengeId, auth.Reason }; break;
            case "reconnect": await client.Events.ReconnectAsync(deadline.Token); result = new { connected = client.Events.IsConnected }; break;
            case "poll": await client.Events.PollAsync(!p.TryGetProperty("acknowledge", out var acknowledge) || acknowledge.GetBoolean(), deadline.Token); result = new { connected = client.Events.IsConnected }; break;
            case "check":
                var decision = await client.AuthorizeAsync(operation, deadline.Token);
                result = new { allowed = decision.IsAuthorized, reason = decision.Reason }; break;
            case "execute":
                int prepared = 0, committed = 0;
                var executed = await client.ExecuteRevalidatedAsync(operation, _ => { prepared++; return ValueTask.CompletedTask; }, _ => { committed++; return ValueTask.CompletedTask; }, deadline.Token);
                result = new { allowed = executed.IsAuthorized, reason = executed.Reason, prepared, invoked = committed }; break;
            case "disconnect": await client.Events.DisconnectAsync(deadline.Token); result = new { connected = false }; break;
            case "state": result = new { connected = client.Events.IsConnected, effectCount = journal.EffectCount, receiptCount = journal.ReceiptCount, versions = journal.Versions }; break;
            case "close": Console.WriteLine(JsonSerializer.Serialize(new { requestId, ok = true, closed = true })); return 0;
            default: throw new InvalidOperationException("Unsupported operation.");
        }
        Console.WriteLine(JsonSerializer.Serialize(new { requestId, ok = true, result }));
    }
    catch (Exception) { Console.WriteLine(JsonSerializer.Serialize(new { requestId, ok = false, error = "operation_failed_closed" })); }
}
return 0;
