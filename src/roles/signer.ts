import { DerError } from "../asn1/der.ts";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { masterKeyFrom } from "../crypto/master.ts";
import { transitStore } from "../dkim/store.ts";
import { method, RpcError, serveRpc } from "../ipc/rpc.ts";
import { NodeCa, NodeCaError } from "../signer/node-ca.ts";
import { loadRecipientKey } from "../signer/recipient-key.ts";
import { dkimKeyFilesIn, Signer, SignerError } from "../signer/signer.ts";
import { b } from "../validate/schema.ts";
import { parseCertificateRequest } from "../x509/issue.ts";
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
  const store = config.dkimStore
    ? transitStore(config.dkimStore.socket, config.dkimStore.mount)
    : null;
  const signer = await Signer.create({
    master,
    keystorePath: `${config.keysDir}/epochs.json`,
    dkimKeyFiles: files,
    dkimDir: `${config.keysDir}/dkim`,
    publicUrl: config.publicUrl,
    store,
  });
  const recipientKey = await loadRecipientKey(`${config.keysDir}/recipients.json`, master);
  const nodeCa = await NodeCa.open(`${config.keysDir}/node-ca.json`, master, store, Date.now());

  const shred = async () => {
    const gone = await signer.shred(config.retentionDays);
    if (gone.length > 0) log.info("destroyed expired body keys", { epochs: gone });
  };
  await shred();

  const server = await serveRpc(sockets(config.runDir).signer, {
    epochKey: method(b.object({}), async () => {
      const k = await signer.epochKey();
      return { epoch: k.epoch, publicKey: k.publicKey.toBase64() };
    }),
    domains: method(b.object({}), () => signer.domains()),
    recipientKey: method(b.object({}), () => recipientKey.toBase64()),
    nodeCa: method(b.object({}), () => nodeCa.trusted()),
    nodeCaStates: method(b.object({}), () => nodeCa.states()),
    rotateNodeCa: method(
      b.object({ step: b.enum(["start", "promote", "finish"]) }),
      async ({ step }) => {
        let dropped: { name: string; storeKey: string | null }[] = [];
        try {
          if (step === "start") await nodeCa.rotateStart(Date.now());
          else if (step === "promote") await nodeCa.promote();
          else dropped = await nodeCa.dropRetiring();
        } catch (err) {
          if (err instanceof NodeCaError) throw new RpcError("invalid", err.message);
          throw err;
        }
        log.info("node CA rotation step", { step, cas: nodeCa.states() });
        return { cas: nodeCa.states(), dropped };
      },
    ),
    issueNodeCertificate: method(
      b.object({
        csr: b.string().max(4000),
        purpose: b.enum(["client", "server"]),
        days: b.number().int().min(1).max(30),
      }),
      async ({ csr, purpose, days }) => {
        let request: Awaited<ReturnType<typeof parseCertificateRequest>>;
        try {
          request = await parseCertificateRequest(Uint8Array.fromBase64(csr));
        } catch (err) {
          throw new RpcError("invalid", err instanceof DerError ? err.message : "bad request");
        }
        const cert = await nodeCa.issue(request.name, request.spki, purpose, days, Date.now());
        log.info("node certificate issued", { name: request.name, purpose, days });
        return { cert, ca: nodeCa.trusted() };
      },
    ),
    ensureKeys: method(
      b.object({
        domain: b.string().regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/),
        selectorBase: b.string().regex(/^[a-z0-9-]{1,40}$/),
      }),
      ({ domain, selectorBase }) => signer.ensureKeys(domain, selectorBase),
    ),
    keyStates: method(
      b.object({ domain: b.string().max(253) }),
      ({ domain }) => signer.publicKeys(domain) ?? [],
    ),
    rotateStart: method(
      b.object({
        domain: b.string().max(253),
        selectorBase: b.string().regex(/^[a-z0-9-]{1,40}$/),
      }),
      ({ domain, selectorBase }) => signer.rotateStart(domain, selectorBase),
    ),
    promote: method(b.object({ domain: b.string().max(253) }), ({ domain }) =>
      signer.promote(domain),
    ),
    dropRetiring: method(b.object({ domain: b.string().max(253) }), ({ domain }) =>
      signer.dropRetiring(domain),
    ),
    signCanary: method(
      b.object({ domain: b.string().max(253), which: b.enum(["active", "next"]) }),
      ({ domain, which }) => signer.signCanary(domain, which),
    ),
    readToken: method(
      b.object({ token: b.string().max(100), url: b.string().max(2000).optional() }),
      ({ token, url }) => signer.readToken(token, url),
    ),
    trackTokens: method(
      b.object({
        id: b.string().regex(MESSAGE_ID),
        opens: b.boolean(),
        urls: b.array(b.string().max(2000)).max(200),
      }),
      ({ id, opens, urls }) => signer.trackTokens(id, opens, urls),
    ),
    webhookSecret: method(b.object({ id: b.string().min(1).max(64) }), ({ id }) =>
      signer.webhookSecret(id),
    ),
    signWebhook: method(
      b.object({
        id: b.string().min(1).max(64),
        msgId: b.string().min(1).max(100),
        timestamp: b.number().int(),
        body: b.string().max(1_000_000),
      }),
      (p) => signer.signWebhook(p.id, p.msgId, p.timestamp, p.body),
    ),
    routeSecret: method(b.object({ id: b.string().min(1).max(64) }), ({ id }) =>
      signer.routeSecret(id),
    ),
    openInbound: method(
      b.object({
        id: b.string().min(1).max(64),
        routeId: b.string().min(1).max(64),
        msgId: b.string().min(1).max(100),
        timestamp: b.number().int(),
        body: sealedBodyWire,
      }),
      async (p) => {
        try {
          return await signer.openInbound(p.id, fromWire(p.body), p.routeId, p.msgId, p.timestamp);
        } catch (err) {
          if (err instanceof SignerError) throw new RpcError(err.code, err.message);
          throw new RpcError("failed", "cannot open this body");
        }
      },
    ),
    open: method(
      b.object({
        messageId: b.string().regex(MESSAGE_ID),
        body: sealedBodyWire,
        lane: b.enum(["transactional", "bulk"]).default("transactional"),
        bounceDomain: b.string().max(253).nullable().default(null),
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
