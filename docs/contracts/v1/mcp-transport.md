# Aegir MCP transport contracts

Foxlin Industries. E1-E source contract qualification; no publication or production release.

The separate runtime MCP host exposes `GET /mcp/tools` and `POST /mcp` at its origin,
without the API host's `/apis` prefix. Its existing `2026-03-26` marker identifies
an Aegir custom authenticated JSON-RPC-over-POST profile. It does not establish
standard MCP Streamable HTTP certification. There is no SSE, batch, transport
session or server-to-client request implementation. HTTP requests independently
authenticate; initialization is stateless, missing initialize params retain legacy
compatibility, and an explicitly different protocolVersion is refused.

Use exactly one current DeveloperKey, AgentKey, BearerToken or legacy SessionToken
credential header. A tool schema or discovery result never grants authority.
Actual original credentials are revalidated within canonical PostgreSQL admission,
including independent history/generation, tenant, current scopes, application and
credential state. Duplicate credential headers and query parameters are refused.
Provided Origin is denied unless explicitly configured in the operator allowlist.

The HTTP registry has twelve tools. Ordinary developer credentials expose nine;
they do not expose assignment administration or protected agent messaging.
The assignment tool requires current Human `platform_admin` plus `admin:full`.
Agent messaging requires an independently authenticated Agent with `agent:message`.
Application-scoped Human/integration management proofs are refused. This surface
does not broker group/license access or Human delegation. Personal identity
resolution and protected decryption are not implied by transaction audit authority.

Requests are bounded to 65,536 UTF8 bytes, depth16, 128 items per collection;
string/numeric IDs are required for calls, strings have length1..128 and integers
use the interoperable safe range. Duplicate JSON properties, batches, unknown
fields and response-shaped inputs are refused. Content-Type is application/json
with optional UTF8 charset; compression is unsupported. Results are bounded to
262,144 bytes plus bounded JSON-RPC wrapper. List projections have 256-row/32KiB
budgets and are refused instead of truncated. A transaction is tenant/size checked
before full materialization. No automatic pagination is advertised.

Protocol failures use top-level `error`; executed tool failures retain legacy
`result.code/message` and add `isError` and safe text content. Results retain
legacy PascalCase structured projections. Send additionally returns
`canonicalEnvelope` with camelCase fields accepted by receive. Binary fields are
base64; envelope headers and ciphertext remain subject to actual cryptographic
verification. The canonical request union includes exact registered input schemas.

JSON-RPC IDs only correlate responses. The optional Idempotency-Key header is
supported for open_transaction, assign_foxlin_developer_key, send_protected_message
and receive_protected_message. Its namespace includes actor, tenant, developer,
application, environment and agent; canonical typed intent excludes the RPC ID.
Changed intent is refused. Current policy and target checks precede replay.
Raw Agent keys and legacy Agent bearer proofs use the same current persisted
application environment before forming a receipt scope. A conflicting signed
environment is refused. An existing empty-environment legacy receipt under that
key is quarantined, including when another current-scope receipt exists. It is
retained for independent reconciliation; the server does not rewrite its context
or admit a replacement effect from missing current-scope evidence.
Immutable invocation records and counted security facts commit with local effects.
History capacity is enforced without eviction. Receive replay acknowledges known
processing and never replays plaintext. A retained ciphertext result does not
authorize fresh delivery. An already admitted envelope is historical evidence;
delivery still checks current sender/recipient Agent lifecycle. Coarse application
restrictions are caller-admission controls, not a newly specified all-party
retroactive ciphertext invalidation protocol.

Cancellation, HTTP499/503/504 and disconnection require reconciliation; they never
prove an external Abort or universal rollback. Only the existing opt-in strict
coordinator/participant protocol supplies strict commit guarantees. Generic API
transaction correlation is not idempotency: if a stdio creation response is lost
before the AGTX ID is learned, do not automatically recreate it or claim reliable
rediscovery by correlation. Retain the unknown outcome for operator investigation.

The SDK stdio host is separate: its twelve tools include security graph/actions
and receipt verification, while HTTP includes developer management and protected
messages. Only four transaction tools are shared. Stdio uses the bounded
2025-03-26 newline UTF8 subset, initialization followed by initialized notification,
one active request/no queue, maximum4096 unique request IDs,64KiB input/256KiB output,
30-second deadlines, no batches or transport resume. Duplicate IDs are refused.
Cancellation aborts backend IO and quarantines the process; fresh startup is
required. Output filters configured credential material, including decoded text
JSON; this can conservatively refuse outputs for short legacy secret components.
The genuine SDK request limit is explicitly aligned to the host's30-second cap.
Transport failures, including an unsupported backend projection, quarantine the
process and require fresh startup. Stdio open_transaction accepts a single-line
declaredAction of at most512characters, matching its retained SDK response
contract. perform_action accepts the four existing canonical action names.

The API's default credential-endpoint budget is10requests per minute; startup
and fresh-authority introspection consume that budget. A429 is a refusal and
never triggers ambient credential fallback or an automatic write retry. Operators
must choose an explicit bounded rate policy for their intended integration load.
Local qualification of one long recovery sequence uses the existing30-per-minute
test-host option; the production defaults and capacity guards are unchanged.

Set AEGIR_BASE_URL, the server-only developer credential, explicit
AEGIR_MCP_EXPECTED_DEVELOPER_ID and optional AEGIR_MCP_CREDENTIAL_MODE.
Default narrowed mode requires a current exact-scope lease; failure refuses startup
or execution. Its execution client receives only the token. Deliberate developer-key
mode is explicit and still establishes/introspects the qualification lease.
Delegated mode is unavailable. Local process access is integration authority,
never proof of a particular Human's consent. Do not expose stdio over a network.
AEGIR_MCP_CERTIFICATE_SHA256 supports an exact leaf pin only for existing explicit
loopback HTTPS qualification; ordinary TLS hostname/time checks remain in force.

The original154 routes,77 operations and92 schemas are preserved by the E1-D
semantic anchor; E1-E adds two modeled operations and24 schemas (79/116).
Original67/78, E1-B68/79 and E1-C76/90 anchors remain immutable. The internal MCP
health route stays inventory-only. Five-language direct HTTP contract consumers
qualify this profile; they do not create typed MCP methods in SDK packages or
claim universal SDK HTTP/stdio parity. All current SDK package versions and
source-only publication metadata remain unchanged.

`x-aegir-context-overlays` supplies the four explicit organization/identity/license/
idempotency annotations absent from nine accepted factor/device operations. Their
accepted operation hashes remain unchanged. Consumers resolve an annotation on
the operation first, then its operationId overlay. The validator requires every
effective annotation; an absent overlay never exempts an operation from checks.
