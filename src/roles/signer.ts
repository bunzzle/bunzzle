import { z } from "zod";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { masterKeyFrom } from "../crypto/master.ts";
import { method, RpcError, serveRpc } from "../ipc/rpc.ts";
import { dkimKeyFilesIn, Signer, SignerError } from "../signer/signer.ts";
import { every, onStop, privateDir, ready } from "./runtime.ts";
import { fromWire, MESSAGE_ID, sealedBodyWire, sockets } from "./wire.ts";

const HOUR = 3_600_000;

export async function runSigner(config: Config, log: Logger, masterText: string) {
  const master = await masterKeyFrom(masterText);
  await privateDir(config.keysDir);
  const files = [
    ...(config.dkimKeyFile ? [config.dkimKeyFile] : []),
    ...(await dkimKeyFilesIn(`${config.keysDir}/dkim`)),
  ];
  const signer = await Signer.create({
    master,
    keystorePath: `${config.keysDir}/epochs.json`,
    dkimKeyFiles: files,
    dkimDir: `${config.keysDir}/dkim`,
    publicUrl: config.publicUrl,
  });

  const shred = async () => {
    const gone = await signer.shred(config.retentionDays);
    if (gone.length > 0) log.info("destroyed expired body keys", { epochs: gone });
  };
  await shred();

  const server = await serveRpc(sockets(config.runDir).signer, {
    epochKey: method(z.object({}), async () => {
      const k = await signer.epochKey();
      return { epoch: k.epoch, publicKey: k.publicKey.toBase64() };
    }),
    domains: method(z.object({}), () => signer.domains()),
    ensureKeys: method(
      z.object({
        domain: z.string().regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/),
        selectorBase: z.string().regex(/^[a-z0-9-]{1,40}$/),
      }),
      ({ domain, selectorBase }) => signer.ensureKeys(domain, selectorBase),
    ),
    readToken: method(z.object({ token: z.string().max(100) }), ({ token }) =>
      signer.readToken(token),
    ),
    webhookSecret: method(z.object({ id: z.string().min(1).max(64) }), ({ id }) =>
      signer.webhookSecret(id),
    ),
    signWebhook: method(
      z.object({
        id: z.string().min(1).max(64),
        msgId: z.string().min(1).max(100),
        timestamp: z.number().int(),
        body: z.string().max(1_000_000),
      }),
      (p) => signer.signWebhook(p.id, p.msgId, p.timestamp, p.body),
    ),
    open: method(
      z.object({
        messageId: z.string().regex(MESSAGE_ID),
        body: sealedBodyWire,
        lane: z.enum(["transactional", "bulk"]).default("transactional"),
        bounceDomain: z.string().max(253).nullable().default(null),
      }),
      async ({ messageId, body, lane, bounceDomain }) => {
        try {
          return await signer.open(messageId, fromWire(body), { lane, bounceDomain });
        } catch (err) {
          if (err instanceof SignerError) {
            if (err.code === "unreadable")
              log.error("a stored body cannot be decrypted", { messageId });
            throw new RpcError(err.code, err.message);
          }
          throw new RpcError("failed", "cannot open this body");
        }
      },
    ),
  });
  const stopShred = every(Math.max(1_000, HOUR * config.retryScale), shred);
  onStop(log, () => {
    stopShred();
    server.stop();
  });
  log.info("signer ready", { domains: signer.domains(), masterKey: master.id });
  ready();
}
