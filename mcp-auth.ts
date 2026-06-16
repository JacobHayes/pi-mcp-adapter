/**
 * MCP Auth Storage Module
 * 
 * Handles secure storage of OAuth credentials, tokens, client information,
 * and PKCE state for MCP servers.
 * 
 * Default storage location: system keyring, under service
 * `pi-mcp-adapter.oauth` and account `sha256-<agent-dir+server-hash>`. The
 * account incorporates the agent dir so PI_CODING_AGENT_DIR-isolated profiles
 * do not collide on a shared server name.
 *
 * Explicit file storage/testing override: when $MCP_OAUTH_DIR is set, auth
 * entries are stored at $MCP_OAUTH_DIR/sha256-<server-hash>/tokens.json.
 * Legacy file entries under <Pi agent dir>/mcp-oauth are migrated into the
 * keyring on first read when keyring storage is active.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { getAgentDir, getAgentPath } from './agent-dir.ts';
import { deleteKeyringSecret, readKeyringSecret, writeKeyringSecret } from './mcp-auth-keyring.ts';

/** OAuth token storage format */
export interface StoredTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number; // Unix timestamp in seconds
  scope?: string;
}

/** OAuth client information from dynamic or static registration */
export interface StoredClientInfo {
  clientId: string;
  clientSecret?: string;
  clientIdIssuedAt?: number;
  clientSecretExpiresAt?: number;
  redirectUris?: string[];
}

/** Complete auth entry for a server */
export interface AuthEntry {
  tokens?: StoredTokens;
  clientInfo?: StoredClientInfo;
  codeVerifier?: string;
  oauthState?: string;
  serverUrl?: string; // Track the URL these credentials are for
}

type AuthStorageBackend = 'keyring' | 'file';

// Base directory for legacy/file auth storage - can be overridden via env var for testing.
function getAuthBaseDir(): string {
  const override = process.env.MCP_OAUTH_DIR?.trim();
  return override ? override : getAgentPath('mcp-oauth');
}

function getStorageBackend(): AuthStorageBackend {
  return process.env.MCP_OAUTH_DIR?.trim() ? 'file' : 'keyring';
}

function assertValidServerName(serverName: string): void {
  if (typeof serverName !== 'string') {
    throw new Error(`Invalid MCP server name: ${JSON.stringify(serverName)}`);
  }
}

/**
 * Storage key for the legacy/file backend. The file path is already nested
 * under the agent dir (see getAuthBaseDir), so this is scoped by server name
 * only.
 */
function getServerStorageKey(serverName: string): string {
  assertValidServerName(serverName);
  const storageKey = createHash('sha256').update(serverName, 'utf8').digest('hex');
  return `sha256-${storageKey}`;
}

/**
 * Keyring account for a server. Unlike the file backend, the keyring is a flat
 * namespace per OS user, so the account must incorporate the agent dir to keep
 * PI_CODING_AGENT_DIR-isolated profiles from colliding when they share a server
 * name. The null-byte separator prevents dir/name prefix ambiguity.
 */
function getKeyringStorageKey(serverName: string): string {
  assertValidServerName(serverName);
  const storageKey = createHash('sha256')
    .update(getAgentDir(), 'utf8')
    .update('\0')
    .update(serverName, 'utf8')
    .digest('hex');
  return `sha256-${storageKey}`;
}

/**
 * Get the server-specific legacy/file storage directory path.
 */
function getServerDir(serverName: string): string {
  return join(getAuthBaseDir(), getServerStorageKey(serverName));
}

/**
 * Get the legacy/file tokens path for a server.
 *
 * When keyring storage is active this path is only used for migration and for
 * callers that explicitly need to inspect the legacy location.
 */
export function getAuthEntryFilePath(serverName: string): string {
  return join(getServerDir(serverName), 'tokens.json');
}

/**
 * Ensure the server directory exists with secure permissions.
 */
function ensureServerDir(serverName: string): void {
  const dir = getServerDir(serverName);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

function parseAuthEntry(data: string, source: string): AuthEntry {
  try {
    return JSON.parse(data) as AuthEntry;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse auth entry from ${source}: ${message}`);
  }
}

/**
 * Read the auth entry for a server from legacy/file storage.
 * Returns undefined if file doesn't exist.
 */
function readFileAuthEntry(serverName: string): AuthEntry | undefined {
  const filePath = getAuthEntryFilePath(serverName);
  if (!existsSync(filePath)) {
    return undefined;
  }
  const data = readFileSync(filePath, 'utf-8');
  return parseAuthEntry(data, filePath);
}

/**
 * Write the auth entry for a server to legacy/file storage with secure permissions.
 */
function writeFileAuthEntry(serverName: string, entry: AuthEntry): void {
  ensureServerDir(serverName);
  const filePath = getAuthEntryFilePath(serverName);
  writeFileSync(filePath, JSON.stringify(entry, null, 2), { mode: 0o600 });
}

function removeFileAuthEntry(serverName: string): void {
  const dir = getServerDir(serverName);
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

function readKeyringAuthEntry(serverName: string): AuthEntry | undefined {
  const storageKey = getKeyringStorageKey(serverName);
  const data = readKeyringSecret(storageKey);
  if (data === undefined) {
    return undefined;
  }
  return parseAuthEntry(data, `system keyring account ${storageKey}`);
}

function writeKeyringAuthEntry(serverName: string, entry: AuthEntry): void {
  writeKeyringSecret(getKeyringStorageKey(serverName), JSON.stringify(entry));
}

function removeKeyringAuthEntry(serverName: string): void {
  deleteKeyringSecret(getKeyringStorageKey(serverName));
}

function readAuthEntry(serverName: string): AuthEntry | undefined {
  if (getStorageBackend() === 'file') {
    return readFileAuthEntry(serverName);
  }

  const keyringEntry = readKeyringAuthEntry(serverName);
  if (keyringEntry) {
    removeFileAuthEntry(serverName);
    return keyringEntry;
  }

  const legacyEntry = readFileAuthEntry(serverName);
  if (!legacyEntry) {
    return undefined;
  }

  writeKeyringAuthEntry(serverName, legacyEntry);
  removeFileAuthEntry(serverName);
  return legacyEntry;
}

function writeAuthEntry(serverName: string, entry: AuthEntry): void {
  if (getStorageBackend() === 'file') {
    writeFileAuthEntry(serverName, entry);
    return;
  }

  writeKeyringAuthEntry(serverName, entry);
  removeFileAuthEntry(serverName);
}

/**
 * Get auth entry for a server.
 */
export function getAuthEntry(serverName: string): AuthEntry | undefined {
  return readAuthEntry(serverName);
}

/**
 * Get auth entry and validate it's for the correct URL.
 * Returns undefined if URL has changed (credentials are invalid).
 */
export function getAuthForUrl(serverName: string, serverUrl: string): AuthEntry | undefined {
  const entry = getAuthEntry(serverName);
  if (!entry) return undefined;

  // If no serverUrl is stored, this is from an old version - consider it invalid
  if (!entry.serverUrl) return undefined;

  // If URL has changed, credentials are invalid
  if (entry.serverUrl !== serverUrl) return undefined;

  return entry;
}

/**
 * Save auth entry for a server.
 */
export function saveAuthEntry(serverName: string, entry: AuthEntry, serverUrl?: string): void {
  // Always update serverUrl if provided
  if (serverUrl) {
    entry.serverUrl = serverUrl;
  }
  writeAuthEntry(serverName, entry);
}

/**
 * Remove auth entry for a server.
 */
export function removeAuthEntry(serverName: string): void {
  if (getStorageBackend() === 'keyring') {
    removeKeyringAuthEntry(serverName);
  }
  removeFileAuthEntry(serverName);
}

/**
 * Update tokens for a server.
 */
export function updateTokens(
  serverName: string, 
  tokens: StoredTokens, 
  serverUrl?: string
): void {
  const entry = getAuthEntry(serverName) ?? {};
  if (serverUrl && entry.serverUrl !== serverUrl) {
    delete entry.clientInfo;
    delete entry.codeVerifier;
    delete entry.oauthState;
  }
  entry.tokens = tokens;
  saveAuthEntry(serverName, entry, serverUrl);
}

/**
 * Update client info for a server.
 */
export function updateClientInfo(
  serverName: string, 
  clientInfo: StoredClientInfo, 
  serverUrl?: string
): void {
  const entry = getAuthEntry(serverName) ?? {};
  if (serverUrl && entry.serverUrl !== serverUrl) {
    delete entry.tokens;
    delete entry.codeVerifier;
    delete entry.oauthState;
  }
  entry.clientInfo = clientInfo;
  saveAuthEntry(serverName, entry, serverUrl);
}

/**
 * Update code verifier for a server.
 */
export function updateCodeVerifier(serverName: string, codeVerifier: string, serverUrl?: string): void {
  const entry = getAuthEntry(serverName) ?? {};
  if (serverUrl && entry.serverUrl !== serverUrl) {
    delete entry.tokens;
    delete entry.clientInfo;
    delete entry.oauthState;
  }
  entry.codeVerifier = codeVerifier;
  saveAuthEntry(serverName, entry, serverUrl);
}

/**
 * Clear code verifier for a server.
 */
export function clearCodeVerifier(serverName: string): void {
  const entry = getAuthEntry(serverName);
  if (entry) {
    delete entry.codeVerifier;
    saveAuthEntry(serverName, entry);
  }
}

/**
 * Update OAuth state for a server.
 */
export function updateOAuthState(serverName: string, state: string, serverUrl?: string): void {
  const entry = getAuthEntry(serverName) ?? {};
  if (serverUrl && entry.serverUrl !== serverUrl) {
    delete entry.tokens;
    delete entry.clientInfo;
    delete entry.codeVerifier;
  }
  entry.oauthState = state;
  saveAuthEntry(serverName, entry, serverUrl);
}

/**
 * Get OAuth state for a server.
 */
export function getOAuthState(serverName: string): string | undefined {
  const entry = getAuthEntry(serverName);
  return entry?.oauthState;
}

/**
 * Clear OAuth state for a server.
 */
export function clearOAuthState(serverName: string): void {
  const entry = getAuthEntry(serverName);
  if (entry) {
    delete entry.oauthState;
    saveAuthEntry(serverName, entry);
  }
}

/**
 * Check if stored tokens are expired.
 * Returns null if no tokens exist, false if no expiry or not expired, true if expired.
 */
export function isTokenExpired(serverName: string): boolean | null {
  const entry = getAuthEntry(serverName);
  if (!entry?.tokens) return null;
  if (!entry.tokens.expiresAt) return false;
  return entry.tokens.expiresAt < Date.now() / 1000;
}

/**
 * Check if a server has stored tokens.
 */
export function hasStoredTokens(serverName: string): boolean {
  const entry = getAuthEntry(serverName);
  return !!entry?.tokens;
}

/**
 * Clear all credentials for a server.
 */
export function clearAllCredentials(serverName: string): void {
  removeAuthEntry(serverName);
}

/**
 * Clear only client info for a server.
 */
export function clearClientInfo(serverName: string): void {
  const entry = getAuthEntry(serverName);
  if (entry) {
    delete entry.clientInfo;
    saveAuthEntry(serverName, entry);
  }
}

/**
 * Clear only tokens for a server.
 */
export function clearTokens(serverName: string): void {
  const entry = getAuthEntry(serverName);
  if (entry) {
    delete entry.tokens;
    saveAuthEntry(serverName, entry);
  }
}
