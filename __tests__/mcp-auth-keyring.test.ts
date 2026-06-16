import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { setKeyringModuleForTests } from "../mcp-auth-keyring.ts";

class MockEntry {
  constructor(
    private readonly service: string,
    private readonly account: string,
  ) {}

  setPassword(password: string): void {
    mockStore.set(`${this.service}:${this.account}`, password);
  }

  getPassword(): string | null {
    return mockStore.get(`${this.service}:${this.account}`) ?? null;
  }

  deletePassword(): boolean {
    return mockStore.delete(`${this.service}:${this.account}`);
  }
}

const mockStore = new Map<string, string>();

describe("mcp-auth keyring storage", () => {
  const originalOAuthDir = process.env.MCP_OAUTH_DIR;
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  let agentDir: string;

  beforeEach(() => {
    mockStore.clear();
    setKeyringModuleForTests({ Entry: MockEntry });
    agentDir = mkdtempSync(join(tmpdir(), "pi-mcp-auth-keyring-agent-"));
    process.env.PI_CODING_AGENT_DIR = agentDir;
    delete process.env.MCP_OAUTH_DIR;
  });

  afterEach(() => {
    setKeyringModuleForTests(undefined);
    if (originalOAuthDir === undefined) {
      delete process.env.MCP_OAUTH_DIR;
    } else {
      process.env.MCP_OAUTH_DIR = originalOAuthDir;
    }
    if (originalAgentDir === undefined) {
      delete process.env.PI_CODING_AGENT_DIR;
    } else {
      process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    }
    rmSync(agentDir, { recursive: true, force: true });
    mockStore.clear();
  });

  it("stores the entire auth entry in the keyring without writing tokens.json", async () => {
    const { getAuthEntry, getAuthEntryFilePath, saveAuthEntry } = await import("../mcp-auth.ts");

    saveAuthEntry("demo", {
      tokens: { accessToken: "access", refreshToken: "refresh" },
      clientInfo: { clientId: "client", clientSecret: "secret" },
      codeVerifier: "verifier",
      oauthState: "state",
    }, "https://example.com/mcp");

    expect(getAuthEntry("demo")).toEqual({
      tokens: { accessToken: "access", refreshToken: "refresh" },
      clientInfo: { clientId: "client", clientSecret: "secret" },
      codeVerifier: "verifier",
      oauthState: "state",
      serverUrl: "https://example.com/mcp",
    });
    expect(existsSync(getAuthEntryFilePath("demo"))).toBe(false);

    const storedJson = [...mockStore.values()][0];
    expect(JSON.parse(storedJson)).toMatchObject({
      tokens: { accessToken: "access", refreshToken: "refresh" },
      clientInfo: { clientSecret: "secret" },
      codeVerifier: "verifier",
      oauthState: "state",
    });
  });

  it("migrates a legacy file entry into the keyring on first read", async () => {
    const { getAuthEntry, getAuthEntryFilePath } = await import("../mcp-auth.ts");
    const legacyPath = getAuthEntryFilePath("legacy");
    mkdirSync(dirname(legacyPath), { recursive: true });
    writeFileSync(legacyPath, JSON.stringify({
      tokens: { accessToken: "legacy-access", refreshToken: "legacy-refresh" },
      clientInfo: { clientId: "legacy-client", clientSecret: "legacy-secret" },
      serverUrl: "https://legacy.example.com/mcp",
    }), "utf-8");

    expect(getAuthEntry("legacy")?.tokens?.accessToken).toBe("legacy-access");
    expect(existsSync(legacyPath)).toBe(false);
    expect([...mockStore.values()].map((value) => JSON.parse(value))).toContainEqual({
      tokens: { accessToken: "legacy-access", refreshToken: "legacy-refresh" },
      clientInfo: { clientId: "legacy-client", clientSecret: "legacy-secret" },
      serverUrl: "https://legacy.example.com/mcp",
    });
  });

  it("removes keyring and legacy file entries on logout/clear", async () => {
    const { clearAllCredentials, getAuthEntry, getAuthEntryFilePath, saveAuthEntry } = await import("../mcp-auth.ts");
    saveAuthEntry("remove", { tokens: { accessToken: "access" } }, "https://example.com/mcp");

    const legacyPath = getAuthEntryFilePath("remove");
    mkdirSync(dirname(legacyPath), { recursive: true });
    writeFileSync(legacyPath, JSON.stringify({ tokens: { accessToken: "stale" } }), "utf-8");

    clearAllCredentials("remove");

    expect(getAuthEntry("remove")).toBeUndefined();
    expect(existsSync(legacyPath)).toBe(false);
    expect(mockStore.size).toBe(0);
  });

  it("isolates credentials between agent dirs sharing a server name", async () => {
    const { getAuthEntry, saveAuthEntry } = await import("../mcp-auth.ts");

    // Profile A saves credentials for "shared".
    process.env.PI_CODING_AGENT_DIR = agentDir;
    saveAuthEntry("shared", { tokens: { accessToken: "profile-a" } }, "https://a.example.com/mcp");

    // Profile B uses a different agent dir but the same server name.
    const agentDirB = mkdtempSync(join(tmpdir(), "pi-mcp-auth-keyring-agent-b-"));
    try {
      process.env.PI_CODING_AGENT_DIR = agentDirB;
      // Profile B must not see profile A's credentials.
      expect(getAuthEntry("shared")).toBeUndefined();

      saveAuthEntry("shared", { tokens: { accessToken: "profile-b" } }, "https://b.example.com/mcp");
      expect(getAuthEntry("shared")?.tokens?.accessToken).toBe("profile-b");

      // Profile A's credentials remain intact and distinct.
      process.env.PI_CODING_AGENT_DIR = agentDir;
      expect(getAuthEntry("shared")?.tokens?.accessToken).toBe("profile-a");
    } finally {
      rmSync(agentDirB, { recursive: true, force: true });
    }
  });

  it("keeps MCP_OAUTH_DIR as an explicit file-storage override", async () => {
    process.env.MCP_OAUTH_DIR = mkdtempSync(join(tmpdir(), "pi-mcp-auth-keyring-file-"));
    const fileDir = process.env.MCP_OAUTH_DIR;
    try {
      const { getAuthEntryFilePath, saveAuthEntry } = await import("../mcp-auth.ts");
      saveAuthEntry("file-mode", { tokens: { accessToken: "file-access" } }, "https://example.com/mcp");

      expect(mockStore.size).toBe(0);
      expect(JSON.parse(readFileSync(getAuthEntryFilePath("file-mode"), "utf-8"))).toMatchObject({
        tokens: { accessToken: "file-access" },
      });
    } finally {
      rmSync(fileDir, { recursive: true, force: true });
      delete process.env.MCP_OAUTH_DIR;
    }
  });
});
