import { ConfigError } from "../config.ts";
import type { LinkTls } from "../ipc/rpc.ts";
import type { Peers } from "../nodes/node.ts";

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
  const [cert, key, ca] = await Promise.all([
    read("cert.pem").then((f) => f.text()),
    keyFile.text(),
    read("ca.pem").then((f) => f.text()),
  ]);
  const peers = await loadPeers(dir);
  return { cert, key, ca, pins: [...peers.core, ...peers.delivery] };
}

const pinsIn = (text: string) =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

export async function loadPeers(dir: string): Promise<Peers> {
  const coreFile = Bun.file(`${dir}/peer.pin`);
  if (!(await coreFile.exists())) throw new ConfigError(`node link: ${dir}/peer.pin is missing`);
  const core = pinsIn(await coreFile.text());
  if (core.length === 0 || !core.every((p) => PIN.test(p))) {
    throw new ConfigError(`node link: ${dir}/peer.pin needs one sha256/<base64> pin per line`);
  }
  const deliveryFile = Bun.file(`${dir}/delivery.pin`);
  const delivery = (await deliveryFile.exists()) ? pinsIn(await deliveryFile.text()) : [];
  if (!delivery.every((p) => PIN.test(p))) {
    throw new ConfigError(`node link: ${dir}/delivery.pin needs one sha256/<base64> pin per line`);
  }
  return { core, delivery };
}
