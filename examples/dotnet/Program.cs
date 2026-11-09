// Aegir Beta-1 .NET sample.
//
// Uses only the supported public surface of the Foxlin.Aegir.Security package: the
// AegirSecurityHttpClient facade and the request/response models in Foxlin.Aegir.Auth.Client.
// Nothing here reaches into implementation types, which is deliberate - if a capability is not
// public, this file does not compile, and that is the check.
//
// Run against a hosted or local Aegir API:
//   set AEGIR_BASE_URL=https://api.aegir.foxlinindustries.com/apis
//   set AEGIR_DEVELOPER_KEY=devkey_id:secret
//   dotnet run
//
// With no environment set it prints the available surface and exits, so the sample is useful
// as a compile check on its own.

using Foxlin.Aegir.Auth.Client;
using Foxlin.Aegir.Auth.Services;

string? baseUrl = Environment.GetEnvironmentVariable("AEGIR_BASE_URL");
string? developerKey = Environment.GetEnvironmentVariable("AEGIR_DEVELOPER_KEY");

var client = new AegirSecurityHttpClient(new AegirSecurityClientOptions
{
    BaseUrl = baseUrl ?? "https://api.aegir.foxlinindustries.com/apis",
    DeveloperKey = developerKey
});

Console.WriteLine("Aegir Beta-1 capability groups:");
Console.WriteLine("  client.Tokens        authentication and token lifecycle");
Console.WriteLine("  client.Agents        AI agent identity and provider binding");
Console.WriteLine("  client.Transactions  transactions, event history, signed receipts");
Console.WriteLine("  client.Ai            provider invocation and protected messaging");
Console.WriteLine("  client.ScanIdentity  identity graph, exposure and reversible actions");

if (string.IsNullOrWhiteSpace(developerKey))
{
    Console.WriteLine();
    Console.WriteLine("Set AEGIR_BASE_URL and AEGIR_DEVELOPER_KEY to run the live walkthrough.");
    return 0;
}

// 1. Exchange the developer key for a scope-narrowed token.
//
// Prefer this over presenting the developer key on every request: the token carries only the
// scopes asked for and it expires, whereas a developer key is long-lived and fully privileged.
AegirAccessToken token = await client.Tokens.UseNarrowedTokenAsync(
    "agent:read agent:write transaction:read transaction:write");

Console.WriteLine();
Console.WriteLine($"Token acquired: {token.Token_Type}, scopes: {string.Join(" ", token.Scopes)}");

// 2. Register two agent identities.
//
// An agent is a principal in its own right, distinct from the developer key that manages it.
// The agent key is returned once and never again - Aegir stores only a hash.
AegirAgentRegistration alpha = await client.Agents.RegisterAsync(
    new AegirRegisterAgentRequest(
        "sample-alpha",
        Scopes: ["agent:message", "transaction:write"]));

AegirAgentRegistration beta = await client.Agents.RegisterAsync(
    new AegirRegisterAgentRequest(
        "sample-beta",
        Scopes: ["agent:message", "transaction:write"]));

Console.WriteLine($"Agents registered: {alpha.Agent.AgentId}, {beta.Agent.AgentId}");

// 3. Each agent authenticates as itself, on its own client.
string apiBaseUrl = baseUrl ?? "https://api.aegir.foxlinindustries.com/apis";
var alphaClient = new AegirSecurityHttpClient(new AegirSecurityClientOptions { BaseUrl = apiBaseUrl });
await alphaClient.Tokens.UseAgentKeyAsync(alpha.AgentKey);

var betaClient = new AegirSecurityHttpClient(new AegirSecurityClientOptions { BaseUrl = apiBaseUrl });
await betaClient.Tokens.UseAgentKeyAsync(beta.AgentKey);

// 4. Open a transaction BEFORE the protected operation.
//
// That ordering is the point: a denied or abandoned attempt is as auditable as a successful one.
AegirTransactionSummary transaction = await alphaClient.Transactions.CreateAsync(
    new AegirCreateTransactionRequest("agent.message.send"));

Console.WriteLine($"Transaction opened: {transaction.TransactionId} ({transaction.Status})");

// 5. Protect a payload from alpha to beta.
//
// The envelope is ML-KEM-768 key establishment, AES-256-GCM encryption and an ML-DSA-65
// signature, bound to this transaction. Relay it unchanged: every field is authenticated, so an
// edit anywhere makes it fail validation at the recipient.
string payload = Convert.ToBase64String("{\"finding\":\"CVE-2026-0001\"}"u8.ToArray());

AegirProtectedMessage message = await alphaClient.Ai.SendProtectedMessageAsync(
    new AegirSendProtectedMessageRequest(
        transaction.TransactionId,
        beta.Agent.AgentId,
        "agent.finding.share",
        payload));

Console.WriteLine(
    $"Protected: {message.KemAlgorithm} / {message.SignatureAlgorithm} / {message.AeadAlgorithm}");

// 6. Only the addressed agent can open it.
AegirProtectedDelivery delivery = await betaClient.Ai.ReceiveProtectedMessageAsync(message);
Console.WriteLine($"Delivered from {delivery.SenderAgentId}, action '{delivery.Action}'");

// 7. Pull the signed receipt and verify it.
//
// A receipt carries verification assertions, never underlying data: evidence hashes and the
// decision, no personal identity and no payload. Reading it requires transaction:read, which is
// audit authority only - it never resolves a principal to a person and never decrypts anything.
AegirTransactionReceipt receipt = await client.Transactions.GetReceiptAsync(transaction.TransactionId);
AegirReceiptVerification verification = await client.Transactions.VerifyReceiptAsync(receipt);

Console.WriteLine($"Receipt {receipt.Algorithm}: valid={verification.Valid} ({verification.Status})");

// 8. A tampered receipt does not verify.
AegirReceiptVerification tampered = await client.Transactions.VerifyReceiptAsync(
    receipt with { DeclaredAction = "agent.credential.export" });

Console.WriteLine($"Tampered receipt: valid={tampered.Valid} ({tampered.Status})");

return verification.Valid && !tampered.Valid ? 0 : 1;
