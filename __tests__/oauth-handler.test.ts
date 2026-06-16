import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("oauth-handler", () => {
  const originalOAuthDir = process.env.MCP_OAUTH_DIR;
  let authDir: string;

  beforeEach(() => {
    vi.resetModules();
    authDir = mkdtempSync(join(tmpdir(), "pi-mcp-oauth-handler-"));
    process.env.MCP_OAUTH_DIR = authDir;
  });

  afterEach(() => {
    if (originalOAuthDir === undefined) {
      delete process.env.MCP_OAUTH_DIR;
    } else {
      process.env.MCP_OAUTH_DIR = originalOAuthDir;
    }
    rmSync(authDir, { recursive: true, force: true });
  });

  it("reads tokens through the shared auth storage layer", async () => {
    const { saveAuthEntry } = await import("../mcp-auth.ts");
    saveAuthEntry("demo", {
      tokens: {
        accessToken: "abc",
        refreshToken: "refresh",
        scope: "read",
      },
    });

    const { getStoredTokens } = await import("../oauth-handler.ts");
    expect(getStoredTokens("demo")).toEqual({
      access_token: "abc",
      token_type: "bearer",
      refresh_token: "refresh",
      expires_in: undefined,
      scope: "read",
    });
  });

  it("does not return expired tokens", async () => {
    const { saveAuthEntry } = await import("../mcp-auth.ts");
    saveAuthEntry("expired", {
      tokens: {
        accessToken: "abc",
        expiresAt: Math.floor(Date.now() / 1000) - 60,
      },
    });

    const { getStoredTokens } = await import("../oauth-handler.ts");
    expect(getStoredTokens("expired")).toBeUndefined();
  });
});
