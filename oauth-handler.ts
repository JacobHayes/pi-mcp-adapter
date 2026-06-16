// oauth-handler.ts - OAuth token management for MCP servers
import type { OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { getAuthEntry } from "./mcp-auth.ts";

/**
 * Get stored OAuth tokens for a server (if any).
 * Returns undefined if no tokens exist or if they are expired.
 */
export function getStoredTokens(serverName: string): OAuthTokens | undefined {
  const tokens = getAuthEntry(serverName)?.tokens;
  if (!tokens) return undefined;

  if (tokens.expiresAt && tokens.expiresAt < Date.now() / 1000) {
    return undefined;
  }

  return {
    access_token: tokens.accessToken,
    token_type: "bearer",
    refresh_token: tokens.refreshToken,
    expires_in: tokens.expiresAt
      ? Math.max(0, Math.floor(tokens.expiresAt - Date.now() / 1000))
      : undefined,
    scope: tokens.scope,
  };
}
