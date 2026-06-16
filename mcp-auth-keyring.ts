import { createRequire } from 'node:module';

const KEYRING_SERVICE = 'pi-mcp-adapter.oauth';

interface KeyringEntry {
  setPassword(password: string): void;
  getPassword(): string | null;
  deletePassword(): boolean;
}

interface KeyringModule {
  Entry: new (service: string, username: string) => KeyringEntry;
}

const require = createRequire(import.meta.url);
let loadedKeyring: KeyringModule | undefined;
let keyringOverride: KeyringModule | undefined;

function loadKeyring(): KeyringModule {
  if (keyringOverride) return keyringOverride;
  if (loadedKeyring) return loadedKeyring;

  try {
    loadedKeyring = require('@napi-rs/keyring') as KeyringModule;
    return loadedKeyring;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `System keyring storage is unavailable: ${message}. ` +
      `Install dependencies for @napi-rs/keyring or set MCP_OAUTH_DIR to an explicit secure directory to use file-based OAuth storage.`
    );
  }
}

function entryForAccount(account: string): KeyringEntry {
  const { Entry } = loadKeyring();
  return new Entry(KEYRING_SERVICE, account);
}

/** @internal Test hook for keyring-backed storage tests. */
export function setKeyringModuleForTests(module: KeyringModule | undefined): void {
  keyringOverride = module;
  loadedKeyring = undefined;
}

function keyringOperationError(action: string, error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  return new Error(`Failed to ${action} OAuth credentials in the system keyring: ${message}`);
}

export function readKeyringSecret(account: string): string | undefined {
  try {
    return entryForAccount(account).getPassword() ?? undefined;
  } catch (error) {
    throw keyringOperationError('read', error);
  }
}

export function writeKeyringSecret(account: string, secret: string): void {
  try {
    entryForAccount(account).setPassword(secret);
  } catch (error) {
    throw keyringOperationError('write', error);
  }
}

export function deleteKeyringSecret(account: string): void {
  try {
    entryForAccount(account).deletePassword();
  } catch (error) {
    throw keyringOperationError('delete', error);
  }
}

export { KEYRING_SERVICE };
