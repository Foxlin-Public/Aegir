// Compile-only package consumer: resolve the public conditional types without a local source alias.
import { AegirSecurityClient, computePayloadDigest, verifyChallengePayload, signChallengePayload } from "@foxlin_industries/aegir-security";

const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis" });
const digest: string = computePayloadDigest(new Uint8Array([97, 98, 99]));
const rejected: boolean = verifyChallengePayload(new Uint8Array([97]), new Uint8Array([1]));
const retiredSigner: (payload: Uint8Array) => Uint8Array = signChallengePayload;
void [client, digest, rejected, retiredSigner];

