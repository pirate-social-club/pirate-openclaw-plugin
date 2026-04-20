import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const DEFAULT_DISPLAY_NAME = "OpenClaw Agent";
const CONNECTION_STORE_VERSION = 1;
const POLLABLE_TERMINAL_STATUSES = new Set(["verified", "failed", "expired", "cancelled"]);
const VALID_CONNECTION_STATUSES = new Set(["pending", "awaiting_owner", "verified", "failed", "expired", "cancelled"]);
const COMMUNITY_ID_PATTERN = /\b(cmt_[a-zA-Z0-9]+)\b/;
const COMMUNITY_ROUTE_PATTERN = /\/c\/([^/\s)]+)/i;

export function normalizeApiBaseUrl(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("Pirate API base URL is required");
  }

  const parsed = new URL(value.trim());
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Pirate API base URL must use http or https");
  }

  const normalized = parsed.toString();
  return normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

export function normalizePirateCommunityIdentifier(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("Pirate community identifier is required");
  }

  const trimmed = value.trim();
  const cmtMatch = trimmed.match(COMMUNITY_ID_PATTERN);
  if (cmtMatch) {
    return cmtMatch[1];
  }

  const routeMatch = trimmed.match(COMMUNITY_ROUTE_PATTERN);
  if (routeMatch?.[1]) {
    return routeMatch[1].trim();
  }

  try {
    const url = new URL(trimmed);
    const urlRouteMatch = url.pathname.match(/^\/c\/([^/]+)/i);
    if (urlRouteMatch?.[1]) {
      return urlRouteMatch[1].trim();
    }
  } catch {
    // Fall through to raw slug normalization.
  }

  return trimmed.replace(/^\/+/, "").replace(/^c\//i, "").trim();
}

function classifyPirateCommunityIdentifier(value) {
  const trimmed = String(value ?? "").trim();
  if (COMMUNITY_ID_PATTERN.test(trimmed)) {
    return "id";
  }
  if (COMMUNITY_ROUTE_PATTERN.test(trimmed)) {
    return "route";
  }
  try {
    const url = new URL(trimmed);
    if (/^\/c\/([^/]+)/i.test(url.pathname)) {
      return "route";
    }
  } catch {
    // Ignore parse errors and fall through.
  }
  return "name";
}

function requireEd25519PrivateKey(privateKeyPem) {
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("Only Ed25519 identities are supported");
  }
  return key;
}

function requireObjectResponse(payload, message) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error(message);
  }
  return payload;
}

function requireStringField(payload, key, message) {
  if (typeof payload[key] !== "string" || payload[key].trim().length === 0) {
    throw new Error(message);
  }
  return payload[key];
}

export function buildClawkeyChallenge(identity, input = {}) {
  if (
    !identity
    || typeof identity.deviceId !== "string"
    || typeof identity.publicKeyPem !== "string"
    || typeof identity.privateKeyPem !== "string"
  ) {
    throw new Error("OpenClaw identity is missing deviceId/publicKeyPem/privateKeyPem");
  }

  const timestamp = Number.isFinite(input.timestamp) ? Number(input.timestamp) : Date.now();
  const message = typeof input.message === "string" && input.message.trim().length > 0
    ? input.message
    : `clawkey-register-${timestamp}`;
  const publicKeyDer = createPublicKey(identity.publicKeyPem).export({ type: "spki", format: "der" });
  const signatureBytes = sign(null, Buffer.from(message, "utf8"), requireEd25519PrivateKey(identity.privateKeyPem));

  return {
    device_id: identity.deviceId,
    public_key: publicKeyDer.toString("base64"),
    message,
    signature: signatureBytes.toString("base64"),
    timestamp,
  };
}

export function verifyChallengeSignature(challenge) {
  const publicKey = createPublicKey({
    key: Buffer.from(challenge.public_key, "base64"),
    type: "spki",
    format: "der",
  });

  return verify(
    null,
    Buffer.from(challenge.message, "utf8"),
    publicKey,
    Buffer.from(challenge.signature, "base64"),
  );
}

export async function callPirateJson(input) {
  const response = await input.fetchImpl(input.url, {
    method: input.method,
    headers: {
      accept: "application/json",
      ...(input.body ? { "content-type": "application/json" } : {}),
      ...(input.connectionToken ? { "x-agent-connection-token": input.connectionToken } : {}),
      ...(input.accessToken ? { authorization: `Bearer ${input.accessToken}` } : {}),
      ...(input.headers && typeof input.headers === "object" ? input.headers : {}),
    },
    body: input.body ? JSON.stringify(input.body) : undefined,
  });

  if (response.status === 204 || response.status === 205) {
    return null;
  }

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message = typeof payload?.message === "string"
      ? payload.message
      : `Pirate API request failed with status ${response.status}`;
    throw new Error(message);
  }

  if (!payload || typeof payload !== "object") {
    throw new Error("Pirate API response was not valid JSON");
  }

  return payload;
}

export async function claimPiratePairing(input) {
  const apiBaseUrl = normalizeApiBaseUrl(input.apiBaseUrl);
  const response = requireObjectResponse(await callPirateJson({
    fetchImpl: input.fetchImpl,
    method: "POST",
    url: `${apiBaseUrl}/agent-ownership-pairing/claim`,
    body: {
      pairing_code: input.pairingCode,
      display_name: input.displayName ?? DEFAULT_DISPLAY_NAME,
      agent_challenge: input.agentChallenge,
    },
  }), "Pirate pairing claim response was not valid JSON");

  return {
    apiBaseUrl,
    agentOwnershipSessionId: requireStringField(response, "agent_ownership_session_id", "Pirate pairing claim response is missing agent_ownership_session_id"),
    registrationUrl: requireStringField(response, "registration_url", "Pirate pairing claim response is missing registration_url"),
    connectionToken: requireStringField(response, "connection_token", "Pirate pairing claim response is missing connection_token"),
  };
}

export async function completePirateOwnershipSession(input) {
  const apiBaseUrl = normalizeApiBaseUrl(input.apiBaseUrl);
  const response = await callPirateJson({
    fetchImpl: input.fetchImpl,
    method: "POST",
    url: `${apiBaseUrl}/agent-ownership-sessions/${encodeURIComponent(input.agentOwnershipSessionId)}/complete`,
    connectionToken: input.connectionToken,
    body: {},
  });

  return response;
}

export async function issuePirateDelegatedCredential(input) {
  const apiBaseUrl = normalizeApiBaseUrl(input.apiBaseUrl);
  const response = requireObjectResponse(await callPirateJson({
    fetchImpl: input.fetchImpl,
    method: "POST",
    url: `${apiBaseUrl}/agents/${encodeURIComponent(input.agentId)}/credential`,
    connectionToken: input.connectionToken,
    body: {
      current_ownership_record_id: input.currentOwnershipRecordId ?? undefined,
    },
  }), "Pirate credential response was not valid JSON");

  return {
    apiBaseUrl,
    agentId: requireStringField(response, "agent_id", "Pirate credential response is missing agent_id"),
    currentOwnershipRecordId: requireStringField(response, "current_ownership_record_id", "Pirate credential response is missing current_ownership_record_id"),
    accessToken: requireStringField(response, "access_token", "Pirate credential response is missing access_token"),
    refreshToken: requireStringField(response, "refresh_token", "Pirate credential response is missing refresh_token"),
    expiresAt: requireStringField(response, "expires_at", "Pirate credential response is missing expires_at"),
    refreshExpiresAt: response.refresh_expires_at == null ? null : String(response.refresh_expires_at),
  };
}

export async function refreshPirateDelegatedCredential(input) {
  const apiBaseUrl = normalizeApiBaseUrl(input.apiBaseUrl);
  const response = requireObjectResponse(await callPirateJson({
    fetchImpl: input.fetchImpl,
    method: "POST",
    url: `${apiBaseUrl}/agents/${encodeURIComponent(input.agentId)}/credential/refresh`,
    connectionToken: input.connectionToken,
    body: {
      refresh_token: input.refreshToken,
    },
  }), "Pirate credential refresh response was not valid JSON");

  return {
    apiBaseUrl,
    agentId: requireStringField(response, "agent_id", "Pirate credential refresh response is missing agent_id"),
    currentOwnershipRecordId: requireStringField(response, "current_ownership_record_id", "Pirate credential refresh response is missing current_ownership_record_id"),
    accessToken: requireStringField(response, "access_token", "Pirate credential refresh response is missing access_token"),
    refreshToken: requireStringField(response, "refresh_token", "Pirate credential refresh response is missing refresh_token"),
    expiresAt: requireStringField(response, "expires_at", "Pirate credential refresh response is missing expires_at"),
    refreshExpiresAt: response.refresh_expires_at == null ? null : String(response.refresh_expires_at),
  };
}

export async function findPirateCommunities(input) {
  const apiBaseUrl = normalizeApiBaseUrl(input.apiBaseUrl);
  const url = new URL(`${apiBaseUrl}/public-communities`);
  if (typeof input.query === "string" && input.query.trim()) {
    url.searchParams.set("query", input.query.trim());
  }
  if (Number.isFinite(input.limit) && input.limit > 0) {
    url.searchParams.set("limit", String(Math.trunc(input.limit)));
  }

  const response = requireObjectResponse(await callPirateJson({
    fetchImpl: input.fetchImpl,
    method: "GET",
    url: url.toString(),
  }), "Pirate community search response was not valid JSON");

  return {
    apiBaseUrl,
    query: typeof response.query === "string" ? response.query : null,
    communities: Array.isArray(response.communities)
      ? response.communities.map((community) => ({
        communityId: String(community.community_id),
        displayName: String(community.display_name),
        routeSlug: typeof community.route_slug === "string" ? community.route_slug : null,
      }))
      : [],
  };
}

function normalizeLookupText(value) {
  return String(value ?? "").trim().toLowerCase();
}

export async function resolvePirateCommunityId(input) {
  const identifierKind = classifyPirateCommunityIdentifier(input.communityIdentifier);
  const normalized = normalizePirateCommunityIdentifier(input.communityIdentifier);
  if (normalized.startsWith("cmt_")) {
    return {
      apiBaseUrl: normalizeApiBaseUrl(input.apiBaseUrl),
      communityId: normalized,
      matchedBy: "id",
      communities: [],
    };
  }

  const search = await findPirateCommunities({
    fetchImpl: input.fetchImpl,
    apiBaseUrl: input.apiBaseUrl,
    query: normalized,
    limit: 10,
  });

  const normalizedNeedle = normalizeLookupText(normalized);
  const exactRoute = search.communities.find((community) => normalizeLookupText(community.routeSlug) === normalizedNeedle);
  if (exactRoute) {
    return {
      apiBaseUrl: search.apiBaseUrl,
      communityId: exactRoute.communityId,
      matchedBy: "route_slug",
      communities: search.communities,
    };
  }

  if (identifierKind !== "route") {
    const exactDisplayNameMatches = search.communities.filter((community) =>
      normalizeLookupText(community.displayName) === normalizedNeedle
    );
    if (exactDisplayNameMatches.length === 1) {
      return {
        apiBaseUrl: search.apiBaseUrl,
        communityId: exactDisplayNameMatches[0].communityId,
        matchedBy: "display_name",
        communities: search.communities,
      };
    }
  }

  if (identifierKind === "name" && search.communities.length === 1) {
    return {
      apiBaseUrl: search.apiBaseUrl,
      communityId: search.communities[0].communityId,
      matchedBy: "single_result",
      communities: search.communities,
    };
  }

  if (search.communities.length === 0) {
    throw new Error(`No Pirate community matched "${input.communityIdentifier}"`);
  }

  if (identifierKind === "route") {
    throw new Error(
      `No verified Pirate route matched "${input.communityIdentifier}". Use the cmt_ community id until the community has a real /c/ slug.`,
    );
  }

  throw new Error(
    `Multiple Pirate communities matched "${input.communityIdentifier}". Be more specific or use a cmt_ community id.`,
  );
}

export function isTerminalOwnershipStatus(status) {
  return POLLABLE_TERMINAL_STATUSES.has(status);
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function buildConnectionScopeKey(context = {}) {
  if (typeof context.agentId === "string" && context.agentId.trim()) {
    return `agent:${context.agentId.trim()}`;
  }
  if (typeof context.sessionKey === "string" && context.sessionKey.trim()) {
    return `session:${context.sessionKey.trim()}`;
  }
  if (typeof context.sessionId === "string" && context.sessionId.trim()) {
    return `session-id:${context.sessionId.trim()}`;
  }
  return "default";
}

export function resolvePluginStateFile(stateDir, pluginId) {
  return join(stateDir, "plugins", sha256Hex(pluginId).slice(0, 12), "pirate-connector-state.json");
}

function compareUtf8Ascending(left, right) {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);

  for (let index = 0; index < length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) {
      return leftBytes[index] - rightBytes[index];
    }
  }

  return leftBytes.length - rightBytes.length;
}

function normalizePath(pathname) {
  const trimmed = typeof pathname === "string" ? pathname.trim() : "";
  if (!trimmed || trimmed === "/") {
    return "/";
  }
  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.replace(/\/+$/g, "");
}

function sortJsonValue(value) {
  return sortJsonValueWithSeen(value, new WeakSet());
}

function sortJsonValueWithSeen(value, seen) {
  if (Array.isArray(value)) {
    return value.map((item) => sortJsonValueWithSeen(item, seen));
  }
  if (value && typeof value === "object") {
    if (seen.has(value)) {
      throw new Error("Pirate action proof body cannot contain circular references");
    }
    seen.add(value);
    const entries = Object.entries(value).sort(([left], [right]) => compareUtf8Ascending(left, right));
    return Object.fromEntries(entries.map(([key, child]) => [key, sortJsonValueWithSeen(child, seen)]));
  }
  return value;
}

export function canonicalizePirateActionRequest(input) {
  const url = new URL(input.url);
  const method = String(input.method).trim().toUpperCase();
  const query = Array.from(url.searchParams.entries())
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => {
      const keyCompare = compareUtf8Ascending(leftKey, rightKey);
      if (keyCompare !== 0) {
        return keyCompare;
      }
      return compareUtf8Ascending(leftValue, rightValue);
    })
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
  const body = input.body == null || input.body === ""
    ? ""
    : typeof input.body === "string"
      ? input.body
      : JSON.stringify(sortJsonValue(input.body));

  return [
    "pirate-agent-action-proof-v2",
    method,
    url.origin,
    normalizePath(url.pathname),
    query,
    body,
  ].join("\n");
}

export function computePirateActionRequestHash(input) {
  return sha256Hex(canonicalizePirateActionRequest(input));
}

export function canonicalizePirateActionSignaturePayload(input) {
  return [
    "pirate-agent-action-signature-v2",
    input.nonce.trim(),
    input.signedAt.trim(),
    input.canonicalRequestHash.trim(),
  ].join("\n");
}

export function signPirateActionProof(identity, input) {
  const canonicalRequestHash = computePirateActionRequestHash({
    method: input.method,
    url: input.url,
    body: input.body,
  });
  const nonce = typeof input.nonce === "string" && input.nonce.trim() ? input.nonce.trim() : `nonce_${randomUUID()}`;
  const signedAt = typeof input.signedAt === "string" && input.signedAt.trim()
    ? input.signedAt.trim()
    : new Date().toISOString();
  const payload = canonicalizePirateActionSignaturePayload({
    nonce,
    signedAt,
    canonicalRequestHash,
  });
  const signature = sign(null, Buffer.from(payload, "utf8"), requireEd25519PrivateKey(identity.privateKeyPem)).toString("base64");

  return {
    nonce,
    signed_at: signedAt,
    canonical_request_hash: canonicalRequestHash,
    signature,
  };
}

export async function loadConnectionStore(stateFile) {
  try {
    const raw = await readFile(stateFile, "utf8");
    const parsed = JSON.parse(raw);
    if (
      !parsed
      || typeof parsed !== "object"
      || parsed.version !== CONNECTION_STORE_VERSION
      || !parsed.entries
      || typeof parsed.entries !== "object"
    ) {
      return { version: CONNECTION_STORE_VERSION, current: null, entries: {} };
    }

    return {
      version: CONNECTION_STORE_VERSION,
      current: typeof parsed.current === "string" ? parsed.current : null,
      entries: parsed.entries,
    };
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return { version: CONNECTION_STORE_VERSION, current: null, entries: {} };
    }
    throw error;
  }
}

export async function saveConnectionStore(stateFile, store) {
  await mkdir(dirname(stateFile), { recursive: true });
  const tempFile = `${stateFile}.tmp`;
  await writeFile(tempFile, `${JSON.stringify(store, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(tempFile, stateFile);
}

export function upsertConnectionEntry(store, input) {
  const entries = { ...store.entries };
  const existing = entries[input.scopeKey] && typeof entries[input.scopeKey] === "object"
    ? entries[input.scopeKey]
    : {};

  entries[input.scopeKey] = {
    ...existing,
    scope_key: input.scopeKey,
    api_base_url: input.apiBaseUrl,
    agent_ownership_session_id: input.agentOwnershipSessionId,
    connection_token: input.connectionToken,
    pairing_code: input.pairingCode,
    registration_url: input.registrationUrl,
    status: VALID_CONNECTION_STATUSES.has(input.status)
      ? input.status
      : (VALID_CONNECTION_STATUSES.has(existing.status) ? existing.status : "awaiting_owner"),
    agent_id: input.agentId ?? existing.agent_id ?? null,
    current_ownership_record_id: input.currentOwnershipRecordId ?? existing.current_ownership_record_id ?? null,
    credential_access_token: input.credentialAccessToken ?? existing.credential_access_token ?? null,
    credential_refresh_token: input.credentialRefreshToken ?? existing.credential_refresh_token ?? null,
    credential_expires_at: input.credentialExpiresAt ?? existing.credential_expires_at ?? null,
    credential_refresh_expires_at: input.credentialRefreshExpiresAt ?? existing.credential_refresh_expires_at ?? null,
    verified_at: input.verifiedAt ?? existing.verified_at ?? null,
    updated_at: new Date().toISOString(),
  };

  return {
    version: CONNECTION_STORE_VERSION,
    current: input.scopeKey,
    entries,
  };
}

export function resolveCurrentConnection(store, scopeKey) {
  if (scopeKey && store.entries[scopeKey]) {
    return store.entries[scopeKey];
  }
  if (store.current && store.entries[store.current]) {
    return store.entries[store.current];
  }
  return null;
}
