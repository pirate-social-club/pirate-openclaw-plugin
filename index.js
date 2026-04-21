import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  buildClawkeyChallenge,
  buildConnectionScopeKey,
  callPirateJson,
  claimPiratePairing,
  findPirateCommunities,
  issuePirateDelegatedCredential,
  refreshPirateDelegatedCredential,
  normalizePirateCommunityIdentifier,
  resolvePirateCommunityId,
  signPirateActionProof,
  completePirateOwnershipSession,
  DEFAULT_DISPLAY_NAME,
  isTerminalOwnershipStatus,
  loadConnectionStore,
  normalizeApiBaseUrl,
  resolveCurrentConnection,
  resolvePluginStateFile,
  saveConnectionStore,
  upsertConnectionEntry,
} from "./lib/pirate-connector-core.js";

const PLUGIN_ID = "@pirate_sc/openclaw-pirate-plugin";
const DEFAULT_LOCAL_PIRATE_API_BASE_URL = "http://127.0.0.1:8787";

const pluginConfigSchema = {
  validate(value) {
    if (value == null) {
      return { ok: true, value: {} };
    }
    if (typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, errors: ["Plugin config must be an object."] };
    }

    const candidate = value;
    if (
      "pirateApiBaseUrl" in candidate
      && candidate.pirateApiBaseUrl != null
      && typeof candidate.pirateApiBaseUrl !== "string"
    ) {
      return { ok: false, errors: ["plugins.entries.@pirate_sc/openclaw-pirate-plugin.config.pirateApiBaseUrl must be a string."] };
    }

    return { ok: true, value };
  },
  uiHints: {
    pirateApiBaseUrl: {
      label: "Pirate API Base URL",
      help: "Optional default Pirate API base URL for pairing claims and status checks. If omitted, local installs default to http://127.0.0.1:8787.",
      tags: ["network"],
      placeholder: DEFAULT_LOCAL_PIRATE_API_BASE_URL,
    },
  },
  jsonSchema: {
    type: "object",
    properties: {
      pirateApiBaseUrl: {
        type: "string",
        description: "Optional default Pirate API base URL for pairing claims and status checks. If omitted, local installs default to http://127.0.0.1:8787.",
      },
    },
    additionalProperties: false,
  },
};

class ToolInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "ToolInputError";
    this.status = 400;
  }
}

const VALID_PIRATE_CONNECTION_STATUSES = new Set(["pending", "awaiting_owner", "verified", "failed", "expired", "cancelled"]);

function textResult(text, details) {
  return {
    content: [
      {
        type: "text",
        text,
      },
    ],
    details,
  };
}

function jsonResult(payload) {
  return textResult(JSON.stringify(payload, null, 2), payload);
}

function readStringParam(params, key, options = {}) {
  const { required = false, trim = true, label = key, allowEmpty = false } = options;
  const raw = params && typeof params === "object" ? params[key] : undefined;
  if (typeof raw !== "string") {
    if (required) {
      throw new ToolInputError(`${label} required`);
    }
    return undefined;
  }

  const value = trim ? raw.trim() : raw;
  if (!value && !allowEmpty) {
    if (required) {
      throw new ToolInputError(`${label} required`);
    }
    return undefined;
  }

  return value;
}

function resolveApiBaseUrl(rawParams, pluginConfig) {
  const candidate = readStringParam(rawParams, "api_base_url");
  // Prefer the explicit tool arg, then plugin config.
  const value = candidate
    ?? (typeof pluginConfig?.pirateApiBaseUrl === "string" ? pluginConfig.pirateApiBaseUrl : null)
    ?? DEFAULT_LOCAL_PIRATE_API_BASE_URL;
  return normalizeApiBaseUrl(value);
}

function resolveStoredOrConfiguredApiBaseUrl(rawParams, pluginConfig, current) {
  if (readStringParam(rawParams, "api_base_url")) {
    return resolveApiBaseUrl(rawParams, pluginConfig);
  }

  const candidate = current?.api_base_url ?? pluginConfig?.pirateApiBaseUrl;
  if (typeof candidate !== "string" || candidate.trim().length === 0) {
    throw new ToolInputError("No Pirate API URL configured. Provide api_base_url or set pirateApiBaseUrl in plugin config.");
  }

  return normalizeApiBaseUrl(candidate);
}

function resolveValidatedPirateStatus(status, fallbackStatus) {
  if (typeof status === "string" && VALID_PIRATE_CONNECTION_STATUSES.has(status)) {
    return status;
  }
  return fallbackStatus;
}

async function loadIdentityFromStateDir(api) {
  const stateDir = api.runtime.state.resolveStateDir();
  const identityPath = join(stateDir, "identity", "device.json");
  const raw = await readFile(identityPath, "utf8");
  const parsed = JSON.parse(raw);

  if (
    !parsed
    || typeof parsed !== "object"
    || typeof parsed.deviceId !== "string"
    || typeof parsed.publicKeyPem !== "string"
    || typeof parsed.privateKeyPem !== "string"
  ) {
    throw new ToolInputError(`OpenClaw identity file is invalid: ${identityPath}`);
  }

  return parsed;
}

function getStateFile(api) {
  const stateDir = api.runtime.state.resolveStateDir();
  return resolvePluginStateFile(stateDir, PLUGIN_ID);
}

function readOptionalTrimmedString(rawParams, key) {
  return readStringParam(rawParams, key, { required: false });
}

function resolveCommunityIdentifier(rawParams) {
  const candidate = readOptionalTrimmedString(rawParams, "community_id")
    ?? readOptionalTrimmedString(rawParams, "community");
  if (!candidate) {
    throw new ToolInputError("Community required");
  }
  return candidate;
}

async function saveUpdatedConnection(api, store, current, updates = {}) {
  const updatedStore = upsertConnectionEntry(store, {
    scopeKey: current.scope_key,
    apiBaseUrl: updates.apiBaseUrl ?? current.api_base_url,
    pairingCode: updates.pairingCode ?? current.pairing_code ?? "",
    agentOwnershipSessionId: updates.agentOwnershipSessionId ?? current.agent_ownership_session_id,
    connectionToken: updates.connectionToken ?? current.connection_token,
    registrationUrl: updates.registrationUrl ?? current.registration_url ?? null,
    status: updates.status ?? current.status,
    agentId: updates.agentId ?? current.agent_id ?? null,
    currentOwnershipRecordId: updates.currentOwnershipRecordId ?? current.current_ownership_record_id ?? null,
    credentialAccessToken: updates.credentialAccessToken ?? current.credential_access_token ?? null,
    credentialRefreshToken: updates.credentialRefreshToken ?? current.credential_refresh_token ?? null,
    credentialExpiresAt: updates.credentialExpiresAt ?? current.credential_expires_at ?? null,
    credentialRefreshExpiresAt: updates.credentialRefreshExpiresAt ?? current.credential_refresh_expires_at ?? null,
    verifiedAt: updates.verifiedAt ?? current.verified_at ?? null,
  });
  await saveConnectionStore(getStateFile(api), updatedStore);
  return updatedStore;
}

async function ensureVerifiedPirateConnection(api, toolContext, rawParams) {
  const stateFile = getStateFile(api);
  const store = await loadConnectionStore(stateFile);
  const scopeKey = buildConnectionScopeKey(toolContext);
  const current = resolveCurrentConnection(store, scopeKey);
  if (!current) {
    throw new ToolInputError("No Pirate connection found. Connect Pirate first.");
  }
  if (current.status !== "verified" || !current.agent_id) {
    throw new ToolInputError("Pirate connection is not verified yet. Run the connection check after completing ClawKey verification.");
  }

  const apiBaseUrl = resolveStoredOrConfiguredApiBaseUrl(rawParams, api.pluginConfig, current);

  return { store, current, apiBaseUrl };
}

async function ensurePirateCredential(api, toolContext, rawParams) {
  const { store, current, apiBaseUrl } = await ensureVerifiedPirateConnection(api, toolContext, rawParams);
  const nowMs = Date.now();
  const expiresAtMs = current.credential_expires_at ? Date.parse(current.credential_expires_at) : Number.NaN;
  const shouldRefresh = Boolean(
    current.credential_access_token
    && current.credential_refresh_token
    && Number.isFinite(expiresAtMs)
    && expiresAtMs <= nowMs + 60_000,
  );
  const hasUsableCredential = Boolean(
    current.credential_access_token
    && !Number.isNaN(expiresAtMs)
    && expiresAtMs > nowMs + 60_000,
  );

  if (hasUsableCredential) {
    return {
      apiBaseUrl,
      current,
      accessToken: current.credential_access_token,
      refreshToken: current.credential_refresh_token,
    };
  }

  const issued = shouldRefresh
    ? await refreshPirateDelegatedCredential({
      fetchImpl: fetch,
      apiBaseUrl,
      agentId: current.agent_id,
      connectionToken: current.connection_token,
      refreshToken: current.credential_refresh_token,
    })
    : await issuePirateDelegatedCredential({
      fetchImpl: fetch,
      apiBaseUrl,
      agentId: current.agent_id,
      connectionToken: current.connection_token,
      currentOwnershipRecordId: current.current_ownership_record_id ?? null,
    });

  await saveUpdatedConnection(api, store, current, {
    apiBaseUrl: issued.apiBaseUrl,
    agentId: issued.agentId,
    currentOwnershipRecordId: issued.currentOwnershipRecordId,
    credentialAccessToken: issued.accessToken,
    credentialRefreshToken: issued.refreshToken,
    credentialExpiresAt: issued.expiresAt,
    credentialRefreshExpiresAt: issued.refreshExpiresAt,
    verifiedAt: current.verified_at ?? new Date().toISOString(),
  });

  return {
    apiBaseUrl: issued.apiBaseUrl,
    current: {
      ...current,
      current_ownership_record_id: issued.currentOwnershipRecordId,
      credential_access_token: issued.accessToken,
      credential_refresh_token: issued.refreshToken,
      credential_expires_at: issued.expiresAt,
      credential_refresh_expires_at: issued.refreshExpiresAt,
    },
    accessToken: issued.accessToken,
    refreshToken: issued.refreshToken,
  };
}

function createConnectPirateTool(api, toolContext) {
  return {
    name: "connect_pirate",
    label: "Connect Pirate",
    description: "Use this when the user says things like 'connect to Pirate with code PIR-XXXX-XXXX'. Claims the pairing code with this OpenClaw identity and returns the ClawKey verification link.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        pairing_code: {
          type: "string",
          description: "Pirate pairing code shown in the Pirate web settings page, for example PIR-N9D5-FZ5C.",
        },
        api_base_url: {
          type: "string",
          description: "Optional Pirate API base URL. Defaults to the plugin config value or http://127.0.0.1:8787 in local development.",
        },
        display_name: {
          type: "string",
          description: "Optional display name to register for this agent in Pirate.",
        },
      },
      required: ["pairing_code"],
    },
    execute: async (_toolCallId, rawParams) => {
      const pairingCode = readStringParam(rawParams, "pairing_code", {
        required: true,
        label: "Pairing code",
      });
      const apiBaseUrl = resolveApiBaseUrl(rawParams, api.pluginConfig);
      const displayName = readStringParam(rawParams, "display_name") ?? DEFAULT_DISPLAY_NAME;
      const identity = await loadIdentityFromStateDir(api);
      const challenge = buildClawkeyChallenge(identity);
      const claimed = await claimPiratePairing({
        fetchImpl: fetch,
        apiBaseUrl,
        pairingCode,
        displayName,
        agentChallenge: challenge,
      });

      const scopeKey = buildConnectionScopeKey(toolContext);
      const stateFile = getStateFile(api);
      const store = await loadConnectionStore(stateFile);
      const updatedStore = upsertConnectionEntry(store, {
        scopeKey,
        apiBaseUrl: claimed.apiBaseUrl,
        pairingCode,
        agentOwnershipSessionId: claimed.agentOwnershipSessionId,
        connectionToken: claimed.connectionToken,
        registrationUrl: claimed.registrationUrl,
        status: "awaiting_owner",
      });
      await saveConnectionStore(stateFile, updatedStore);

      return textResult(
        `Open this ClawKey verification link: ${claimed.registrationUrl}`,
        {
          status: "awaiting_owner",
          pairing_code: pairingCode,
          agent_ownership_session_id: claimed.agentOwnershipSessionId,
          registration_url: claimed.registrationUrl,
        },
      );
    },
  };
}

function createCheckPirateConnectionTool(api, toolContext) {
  return {
    name: "check_pirate_connection",
    label: "Check Pirate Connection",
    description: "Use this when the user says things like 'check Pirate connection status'. Checks whether the current Pirate pairing has completed and the agent is now registered.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        api_base_url: {
          type: "string",
          description: "Optional Pirate API base URL. Defaults to the stored pairing value, the plugin config value, or http://127.0.0.1:8787 in local development.",
        },
      },
    },
    execute: async (_toolCallId, rawParams) => {
      const stateFile = getStateFile(api);
      const store = await loadConnectionStore(stateFile);
      const scopeKey = buildConnectionScopeKey(toolContext);
      const current = resolveCurrentConnection(store, scopeKey);
      if (!current) {
        throw new ToolInputError("No pending Pirate connection found. Ask Pirate for a pairing code first.");
      }

      const apiBaseUrl = resolveStoredOrConfiguredApiBaseUrl(rawParams, api.pluginConfig, current);
      const session = await completePirateOwnershipSession({
        fetchImpl: fetch,
        apiBaseUrl,
        agentOwnershipSessionId: current.agent_ownership_session_id,
        connectionToken: current.connection_token,
      });
      const nextStatus = resolveValidatedPirateStatus(session?.status, current.status);

      const updatedStore = upsertConnectionEntry(store, {
        scopeKey: current.scope_key ?? scopeKey,
        apiBaseUrl,
        pairingCode: current.pairing_code ?? "",
        agentOwnershipSessionId: current.agent_ownership_session_id,
        connectionToken: current.connection_token,
        registrationUrl: current.registration_url ?? null,
        status: nextStatus,
        agentId: session.agent_id ?? current.agent_id ?? null,
        currentOwnershipRecordId: session.resolved_agent_ownership_record_id ?? current.current_ownership_record_id ?? null,
        verifiedAt: nextStatus === "verified" ? new Date().toISOString() : current.verified_at ?? null,
      });
      let persistedStore = updatedStore;

      if (nextStatus === "verified") {
        const credential = await issuePirateDelegatedCredential({
          fetchImpl: fetch,
          apiBaseUrl,
          agentId: session.agent_id,
          connectionToken: current.connection_token,
          currentOwnershipRecordId: session.resolved_agent_ownership_record_id ?? null,
        });
        persistedStore = upsertConnectionEntry(updatedStore, {
          scopeKey: current.scope_key ?? scopeKey,
          apiBaseUrl: credential.apiBaseUrl,
          pairingCode: current.pairing_code ?? "",
          agentOwnershipSessionId: current.agent_ownership_session_id,
          connectionToken: current.connection_token,
          registrationUrl: current.registration_url ?? null,
          status: nextStatus,
          agentId: credential.agentId,
          currentOwnershipRecordId: credential.currentOwnershipRecordId,
          credentialAccessToken: credential.accessToken,
          credentialRefreshToken: credential.refreshToken,
          credentialExpiresAt: credential.expiresAt,
          credentialRefreshExpiresAt: credential.refreshExpiresAt,
          verifiedAt: new Date().toISOString(),
        });
        await saveConnectionStore(stateFile, persistedStore);
        return textResult(
          `Pirate connection complete. Agent ${session.agent_id} is verified and ready to post.`,
          {
            status: session.status,
            agent_id: session.agent_id,
            agent_ownership_session_id: session.agent_ownership_session_id,
            current_ownership_record_id: session.resolved_agent_ownership_record_id ?? null,
            credential_expires_at: credential.expiresAt,
          },
        );
      }

      await saveConnectionStore(stateFile, persistedStore);

      if (isTerminalOwnershipStatus(nextStatus)) {
        return jsonResult({
          status: nextStatus,
          failure_reason: session.failure_reason ?? null,
          agent_ownership_session_id: session.agent_ownership_session_id,
        });
      }

      return textResult(
        `Pirate is still waiting for verification: ${nextStatus}.`,
        {
          status: nextStatus,
          agent_ownership_session_id: session.agent_ownership_session_id,
        },
      );
    },
  };
}

function createPostToPirateTool(api, toolContext) {
  return {
    name: "post_to_pirate",
    label: "Post To Pirate",
    description: "Create a top-level text post in Pirate using the verified connected agent. Use this when the user asks to post something to Pirate.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        community_id: {
          type: "string",
          description: "Target Pirate community identifier. Accepts a community id like cmt_123, a route like /c/infinity, a slug like infinity, or a full Pirate community URL.",
        },
        community: {
          type: "string",
          description: "Alias for community_id. Accepts a community id like cmt_123, a route like /c/infinity, a slug like infinity, or a full Pirate community URL.",
        },
        title: {
          type: "string",
          description: "Post title.",
        },
        body: {
          type: "string",
          description: "Post body text.",
        },
        idempotency_key: {
          type: "string",
          description: "Optional idempotency key. One is generated automatically when omitted.",
        },
        api_base_url: {
          type: "string",
          description: "Optional Pirate API base URL override.",
        },
      },
      required: ["title", "body"],
    },
    execute: async (_toolCallId, rawParams) => {
      const communityIdentifier = resolveCommunityIdentifier(rawParams);
      const title = readStringParam(rawParams, "title", { required: true, label: "Title" });
      const bodyText = readStringParam(rawParams, "body", { required: true, label: "Body" });
      const idempotencyKey = readOptionalTrimmedString(rawParams, "idempotency_key") ?? `pirate-post-${randomUUID()}`;
      const identity = await loadIdentityFromStateDir(api);
      const { apiBaseUrl, current, accessToken } = await ensurePirateCredential(api, toolContext, rawParams);
      const communityResolution = await resolvePirateCommunityId({
        fetchImpl: fetch,
        apiBaseUrl,
        communityIdentifier,
      });
      const communityId = communityResolution.communityId;
      const url = `${apiBaseUrl}/communities/${encodeURIComponent(communityId)}/posts`;
      const postPayload = {
        post_type: "text",
        title,
        body: bodyText,
        idempotency_key: idempotencyKey,
        authorship_mode: "user_agent",
        agent_id: current.agent_id,
      };
      const proof = signPirateActionProof(identity, {
        method: "POST",
        url,
        body: postPayload,
      });
      const created = await callPirateJson({
        fetchImpl: fetch,
        method: "POST",
        url,
        accessToken,
        body: {
          ...postPayload,
          agent_action_proof: proof,
        },
      });

      return textResult(
        `Pirate post created: ${created.post_id}`,
        {
          post_id: created.post_id,
          community_id: communityId,
          community_match: communityResolution.matchedBy,
          agent_id: current.agent_id,
          status: created.status ?? null,
        },
      );
    },
  };
}

function createReplyToPirateTool(api, toolContext) {
  return {
    name: "reply_to_pirate",
    label: "Reply To Pirate",
    description: "Create a top-level comment on a Pirate post or a nested reply to a Pirate comment using the verified connected agent.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        community_id: {
          type: "string",
          description: "Required for top-level post comments. Accepts a community id like cmt_123, a route like /c/infinity, a slug like infinity, or a full Pirate community URL. Omit for nested comment replies.",
        },
        community: {
          type: "string",
          description: "Alias for community_id. Accepts a community id like cmt_123, a route like /c/infinity, a slug like infinity, or a full Pirate community URL.",
        },
        post_id: {
          type: "string",
          description: "Post id to comment on.",
        },
        comment_id: {
          type: "string",
          description: "Comment id to reply to. When present, this takes precedence over post_id.",
        },
        body: {
          type: "string",
          description: "Reply body text.",
        },
        api_base_url: {
          type: "string",
          description: "Optional Pirate API base URL override.",
        },
      },
      required: ["body"],
    },
    execute: async (_toolCallId, rawParams) => {
      const bodyText = readStringParam(rawParams, "body", { required: true, label: "Body" });
      const communityRaw = readOptionalTrimmedString(rawParams, "community_id")
        ?? readOptionalTrimmedString(rawParams, "community");
      const postId = readOptionalTrimmedString(rawParams, "post_id");
      const commentId = readOptionalTrimmedString(rawParams, "comment_id");
      if (!commentId && !(communityRaw && postId)) {
        throw new ToolInputError("Provide either comment_id for a nested reply, or both community_id and post_id for a top-level comment.");
      }

      const identity = await loadIdentityFromStateDir(api);
      const { apiBaseUrl, current, accessToken } = await ensurePirateCredential(api, toolContext, rawParams);
      const communityResolution = !commentId
        ? await resolvePirateCommunityId({
          fetchImpl: fetch,
          apiBaseUrl,
          communityIdentifier: communityRaw,
        })
        : null;
      const communityId = communityResolution?.communityId;
      const url = commentId
        ? `${apiBaseUrl}/comments/${encodeURIComponent(commentId)}/replies`
        : `${apiBaseUrl}/communities/${encodeURIComponent(communityId)}/posts/${encodeURIComponent(postId)}/comments`;
      const replyPayload = {
        body: bodyText,
        authorship_mode: "user_agent",
        agent_id: current.agent_id,
      };
      const proof = signPirateActionProof(identity, {
        method: "POST",
        url,
        body: replyPayload,
      });
      const created = await callPirateJson({
        fetchImpl: fetch,
        method: "POST",
        url,
        accessToken,
        body: {
          ...replyPayload,
          agent_action_proof: proof,
        },
      });

      return textResult(
        `Pirate reply created: ${created.comment_id}`,
        {
          comment_id: created.comment_id,
          parent_comment_id: created.parent_comment_id ?? null,
          post_id: postId ?? null,
          community_id: communityId ?? null,
          community_match: communityResolution?.matchedBy ?? null,
          agent_id: current.agent_id,
        },
      );
    },
  };
}

function createFindPirateCommunitiesTool(api) {
  return {
    name: "find_pirate_communities",
    label: "Find Pirate Communities",
    description: "Search Pirate communities by id, route slug, or display name. Use this when the user names a community but does not know the cmt_ id.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        query: {
          type: "string",
          description: "Community id, route slug, /c/slug, or display name to search for.",
        },
        limit: {
          type: "number",
          description: "Optional max number of results to return. Defaults to 5.",
        },
        api_base_url: {
          type: "string",
          description: "Optional Pirate API base URL override.",
        },
      },
      required: ["query"],
    },
    execute: async (_toolCallId, rawParams) => {
      const query = readStringParam(rawParams, "query", { required: true, label: "Query" });
      const limit = Number.isFinite(rawParams?.limit) ? Number(rawParams.limit) : 5;
      const apiBaseUrl = resolveApiBaseUrl(rawParams, api.pluginConfig);
      const results = await findPirateCommunities({
        fetchImpl: fetch,
        apiBaseUrl,
        query: normalizePirateCommunityIdentifier(query),
        limit,
      });

      return jsonResult({
        query: results.query,
        communities: results.communities.map((community) => ({
          community_id: community.communityId,
          display_name: community.displayName,
          route_slug: community.routeSlug,
        })),
      });
    },
  };
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Pirate OpenClaw Plugin",
  description: "Connect OpenClaw identities to Pirate with pairing codes and ClawKey verification, then create Pirate posts and replies as the verified agent.",
  configSchema: pluginConfigSchema,
  register(api) {
    api.registerTool((toolContext) => createConnectPirateTool(api, toolContext));
    api.registerTool((toolContext) => createCheckPirateConnectionTool(api, toolContext));
    api.registerTool(() => createFindPirateCommunitiesTool(api));
    api.registerTool((toolContext) => createPostToPirateTool(api, toolContext));
    api.registerTool((toolContext) => createReplyToPirateTool(api, toolContext));
  },
});
