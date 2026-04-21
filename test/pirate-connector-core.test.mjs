import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildClawkeyChallenge,
  callPirateJson,
  canonicalizePirateActionSignaturePayload,
  canonicalizePirateActionRequest,
  computePirateActionRequestHash,
  findPirateCommunities,
  issuePirateDelegatedCredential,
  loadConnectionStore,
  normalizePirateCommunityIdentifier,
  normalizeApiBaseUrl,
  refreshPirateDelegatedCredential,
  resolvePirateCommunityId,
  resolvePluginStateFile,
  saveConnectionStore,
  sha256Hex,
  signPirateActionProof,
  upsertConnectionEntry,
  verifyChallengeSignature,
} from "../lib/pirate-connector-core.js";

test("normalizeApiBaseUrl trims trailing slash", () => {
  assert.equal(normalizeApiBaseUrl("http://127.0.0.1:8787/"), "http://127.0.0.1:8787");
});

test("normalizeApiBaseUrl rejects unsupported schemes", () => {
  assert.throws(() => normalizeApiBaseUrl("ftp://pirate.test"), /must use http or https/);
});

test("normalizePirateCommunityIdentifier accepts ids, slugs, routes, and URLs", () => {
  assert.equal(normalizePirateCommunityIdentifier("cmt_123"), "cmt_123");
  assert.equal(normalizePirateCommunityIdentifier("/c/infinity"), "infinity");
  assert.equal(normalizePirateCommunityIdentifier("infinity"), "infinity");
  assert.equal(normalizePirateCommunityIdentifier("https://pirate.test/c/infinity"), "infinity");
  assert.equal(
    normalizePirateCommunityIdentifier("the /c/infinity Pirate subreddit (cmt_7ad4fad6214240c486fb320c0b8c247e)"),
    "cmt_7ad4fad6214240c486fb320c0b8c247e",
  );
});

test("buildClawkeyChallenge signs the exact UTF-8 message", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const challenge = buildClawkeyChallenge({
    deviceId: "dev_test_123",
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  }, {
    timestamp: 1738500000000,
  });

  assert.equal(challenge.device_id, "dev_test_123");
  assert.equal(challenge.message, "clawkey-register-1738500000000");
  assert.ok(verifyChallengeSignature(challenge));
});

test("callPirateJson sends JSON and connection token header", async () => {
  let seen;
  const payload = await callPirateJson({
    fetchImpl: async (url, init) => {
      seen = { url, init };
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    method: "POST",
    url: "https://pirate.test/agent-ownership-sessions/abc/complete",
    connectionToken: "agpair_test",
    body: { hello: "world" },
  });

  assert.deepEqual(payload, { ok: true });
  assert.equal(seen.url, "https://pirate.test/agent-ownership-sessions/abc/complete");
  assert.equal(seen.init.headers["x-agent-connection-token"], "agpair_test");
  assert.equal(seen.init.headers["content-type"], "application/json");
  assert.equal(seen.init.body, JSON.stringify({ hello: "world" }));
});

test("callPirateJson allows 204 no-content responses", async () => {
  const payload = await callPirateJson({
    fetchImpl: async () => new Response(null, {
      status: 204,
      headers: { "content-type": "application/json" },
    }),
    method: "POST",
    url: "https://pirate.test/no-content",
  });

  assert.equal(payload, null);
});

test("delegated credential helpers send the connection token header", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({
      agent_id: "agt_123",
      current_ownership_record_id: "aor_123",
      access_token: "agtok_123",
      refresh_token: "agrf_123",
      expires_at: "2026-04-20T12:00:00.000Z",
      refresh_expires_at: "2026-05-20T12:00:00.000Z",
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await issuePirateDelegatedCredential({
    fetchImpl,
    apiBaseUrl: "http://127.0.0.1:8787",
    agentId: "agt_123",
    connectionToken: "agpair_123",
    currentOwnershipRecordId: "aor_123",
  });
  await refreshPirateDelegatedCredential({
    fetchImpl,
    apiBaseUrl: "http://127.0.0.1:8787",
    agentId: "agt_123",
    connectionToken: "agpair_123",
    refreshToken: "agrf_123",
  });

  assert.equal(seen[0].init.headers["x-agent-connection-token"], "agpair_123");
  assert.equal(seen[1].init.headers["x-agent-connection-token"], "agpair_123");
});

test("findPirateCommunities returns lightweight community search results", async () => {
  const results = await findPirateCommunities({
    fetchImpl: async (url) => {
      assert.match(String(url), /\/public-communities\?query=infinity&limit=5$/);
      return new Response(JSON.stringify({
        query: "infinity",
        communities: [
          {
            community_id: "cmt_123",
            display_name: "Infinity",
            route_slug: null,
          },
        ],
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    apiBaseUrl: "http://127.0.0.1:8787",
    query: "infinity",
    limit: 5,
  });

  assert.equal(results.communities[0]?.communityId, "cmt_123");
  assert.equal(results.communities[0]?.displayName, "Infinity");
  assert.equal(results.communities[0]?.routeSlug, null);
});

test("resolvePirateCommunityId requires a real route match for route-like input", async () => {
  await assert.rejects(
    () => resolvePirateCommunityId({
      fetchImpl: async () => new Response(JSON.stringify({
        query: "infinity",
        communities: [
          {
            community_id: "cmt_7ad4fad6214240c486fb320c0b8c247e",
            display_name: "Infinity",
            route_slug: null,
          },
        ],
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
      apiBaseUrl: "http://127.0.0.1:8787",
      communityIdentifier: "/c/infinity",
    }),
    /No verified Pirate route matched/,
  );
});

test("resolvePirateCommunityId can use a unique exact display-name match for plain names", async () => {
  const resolved = await resolvePirateCommunityId({
    fetchImpl: async () => new Response(JSON.stringify({
      query: "infinity",
      communities: [
        {
          community_id: "cmt_7ad4fad6214240c486fb320c0b8c247e",
          display_name: "Infinity",
          route_slug: null,
        },
      ],
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
    apiBaseUrl: "http://127.0.0.1:8787",
    communityIdentifier: "Infinity",
  });

  assert.equal(resolved.communityId, "cmt_7ad4fad6214240c486fb320c0b8c247e");
  assert.equal(resolved.matchedBy, "display_name");
});

test("connection store persists current entry", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "pirate-openclaw-plugin-"));
  const stateFile = resolvePluginStateFile(stateDir, "@piratesc/openclaw-pirate-connector");
  const store = upsertConnectionEntry(
    { version: 1, current: null, entries: {} },
    {
      scopeKey: "default",
      apiBaseUrl: "http://127.0.0.1:8787",
      pairingCode: "PIR-ABCD-EFGH",
      agentOwnershipSessionId: "aos_123",
      connectionToken: "agpair_123",
      registrationUrl: "https://api.clawkey.ai/register/123",
      status: "awaiting_owner",
    },
  );

  await saveConnectionStore(stateFile, store);
  const loaded = await loadConnectionStore(stateFile);
  assert.equal(loaded.current, "default");
  assert.equal(loaded.entries.default.agent_ownership_session_id, "aos_123");
  assert.equal(loaded.entries.default.connection_token, "agpair_123");
  const raw = JSON.parse(await readFile(stateFile, "utf8"));
  assert.equal(raw.entries.default.scope_key, "default");
  const stats = await stat(stateFile);
  assert.equal(stats.mode & 0o777, 0o600);
});

test("signPirateActionProof matches the expected canonical hash and signature payload", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const identity = {
    deviceId: "dev_test_123",
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
  const body = {
    post_type: "text",
    title: "Hello",
    body: "Pirate",
    idempotency_key: "post-key-1",
    authorship_mode: "user_agent",
    agent_id: "agt_123",
  };

  const proof = signPirateActionProof(identity, {
    method: "POST",
    url: "http://pirate.test/communities/cmt_123/posts",
    body,
    nonce: "nonce_123",
    signedAt: "2026-04-20T12:00:00.000Z",
  });

  const expectedHash = computePirateActionRequestHash({
    method: "POST",
    url: "http://pirate.test/communities/cmt_123/posts",
    body,
  });
  assert.equal(proof.canonical_request_hash, expectedHash);

  const verified = verify(
    null,
    Buffer.from(canonicalizePirateActionSignaturePayload({
      nonce: proof.nonce,
      signedAt: proof.signed_at,
      canonicalRequestHash: proof.canonical_request_hash,
    }), "utf8"),
    publicKey,
    Buffer.from(proof.signature, "base64"),
  );
  assert.equal(verified, true);
});

test("canonicalizePirateActionRequest binds the proof to the request origin", () => {
  const canonical = canonicalizePirateActionRequest({
    method: "POST",
    url: "https://pirate.test/communities/cmt_123/posts?draft=false",
    body: { title: "Hello" },
  });

  assert.match(canonical, /^pirate-agent-action-proof-v2\nPOST\nhttps:\/\/pirate\.test\n\/communities\/cmt_123\/posts\ndraft=false\n/);
  assert.notEqual(
    computePirateActionRequestHash({
      method: "POST",
      url: "http://pirate.test/communities/cmt_123/posts?draft=false",
      body: { title: "Hello" },
    }),
    computePirateActionRequestHash({
      method: "POST",
      url: "https://pirate.test/communities/cmt_123/posts?draft=false",
      body: { title: "Hello" },
    }),
  );
});

test("canonicalizePirateActionRequest rejects circular JSON bodies", () => {
  const body = { title: "loop" };
  body.self = body;

  assert.throws(() => canonicalizePirateActionRequest({
    method: "POST",
    url: "https://pirate.test/example",
    body,
  }), /cannot contain circular references/);
});

test("sha256Hex returns deterministic hex", () => {
  assert.equal(
    sha256Hex("pirate"),
    "03bdd14ef87c5b28bc15ed0bebd48fa76451f7cce7e50a0131d2d0f151af55f3",
  );
});
