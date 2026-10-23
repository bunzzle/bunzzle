import { ConfigError } from "../config.ts";
import type { LinkTls } from "../ipc/rpc.ts";

const PIN = /^sha256\/[A-Za-z0-9+/]{43}=$/;

export async function loadLinkTls(dir: string): Promise<LinkTls> {
  const read = async (name: string) => {
    const file = Bun.file(`${dir}/${name}`);
    if (!(await file.exists())) throw new ConfigError(`node link: ${dir}/${name} is missing`);
    return file;
  };
  const keyFile = await read("key.pem");
  if (((await keyFile.stat()).mode & 0o077) !== 0) {
    throw new ConfigError(`node link: ${dir}/key.pem must not be readable by group or others`);
  }
  const [cert, key, ca, pinText] = await Promise.all([
    read("cert.pem").then((f) => f.text()),
    keyFile.text(),
    read("ca.pem").then((f) => f.text()),
    read("peer.pin").then((f) => f.text()),
  ]);
  const pins = pinText
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  if (pins.length === 0 || !pins.every((p) => PIN.test(p))) {
    throw new ConfigError(`node link: ${dir}/peer.pin needs one sha256/<base64> pin per line`);
  }
  return { cert, key, ca, pins };
}
