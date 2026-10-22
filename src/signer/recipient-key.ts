import { type MasterKey, MasterKeyError } from "../crypto/master.ts";
import { b } from "../validate/schema.ts";

const schema = b.object({
  version: b.literal(1),
  masterKeyId: b.string().min(1),
  key: b.string().min(1),
});

const CONTEXT = "bunzzle recipients v1";

export async function loadRecipientKey(path: string, master: MasterKey): Promise<Uint8Array> {
  const f = Bun.file(path);
  if (await f.exists()) {
    const parsed = schema.safeParse(await f.json());
    if (!parsed.success) throw new MasterKeyError(`recipient key ${path} is not valid`);
    if (parsed.data.masterKeyId !== master.id) {
      throw new MasterKeyError(`recipient key ${path} was created with another master key`);
    }
    return master.open(Uint8Array.fromBase64(parsed.data.key), CONTEXT);
  }
  const key = crypto.getRandomValues(new Uint8Array(32));
  const sealed = await master.seal(key, CONTEXT);
  const tmp = `${path}.${crypto.randomUUID()}.tmp`;
  await Bun.write(
    tmp,
    `${JSON.stringify({ version: 1, masterKeyId: master.id, key: sealed.toBase64() }, null, 2)}\n`,
  );
  await Bun.$`chmod 600 ${tmp} && mv -f ${tmp} ${path}`.quiet();
  return key;
}
