import { type MasterKey, MasterKeyError, masterKeyFrom } from "./master.ts";

export interface MasterKeySource {
  masterKey: string | null;
  masterKeyFile: string | null;
}

export async function readMasterKeyText(src: MasterKeySource): Promise<string | null> {
  if (src.masterKey && src.masterKeyFile) {
    throw new MasterKeyError("set BUNZZLE_MASTER_KEY or BUNZZLE_MASTER_KEY_FILE, not both");
  }
  if (src.masterKey) return src.masterKey;
  if (!src.masterKeyFile) return null;
  const f = Bun.file(src.masterKeyFile);
  if (!(await f.exists())) {
    throw new MasterKeyError(`master key file not found: ${src.masterKeyFile}`);
  }
  return (await f.text()).trim();
}

export async function loadMasterKey(src: MasterKeySource): Promise<MasterKey | null> {
  const text = await readMasterKeyText(src);
  return text === null ? null : masterKeyFrom(text);
}
