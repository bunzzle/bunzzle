import type { Database } from "bun:sqlite";
import { fromPem } from "../asn1/der.ts";
import { parseLinkAddress } from "../config.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { type Methods, method, pinOf, type RpcClient, RpcError } from "../ipc/rpc.ts";
import type { NodeHealth } from "../nodes/fleet.ts";
import type { CoreIdentity } from "../nodes/identity.ts";
import type { NodeLinks } from "../nodes/links.ts";
import { addNode, getNode, listNodes, removeNode } from "../nodes/registry.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import { validName } from "../x509/issue.ts";

const NODE_DAYS = 30;
const issued = b.object({ cert: b.string(), ca: b.string() });
const caStates = b.array(
  b.object({
    name: b.string(),
    state: b.enum(["active", "next", "retiring"]),
    notAfter: b.number(),
  }),
);

const droppedCas = b.array(b.object({ name: b.string(), storeKey: b.string().nullable() }));

const same = (a: Uint8Array, c: Uint8Array) =>
  a.length === c.length && a.every((x, i) => x === c[i]);

function trustOf(certPem: string, caPem: string) {
  const cert = parseCertificate(fromPem(certPem)[0] as Uint8Array);
  const cas = fromPem(caPem).map((d) => parseCertificate(d));
  const issuer = cas.find((c) => same(c.subject, cert.issuer));
  return {
    cert,
    ca: issuer?.commonNames[0] ?? "",
    trustedCas: cas.map((c) => c.commonNames[0] ?? ""),
  };
}

export interface NodeDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  identity: CoreIdentity;
  links: NodeLinks;
  health?: () => NodeHealth[];
  deliveryLink?: { upkeep(force?: boolean): Promise<boolean> };
  now?: () => number;
}

export function nodeMethods(deps: NodeDeps): Methods {
  const { db, writer, log, signer, identity, links } = deps;
  const now = deps.now ?? Date.now;

  const rotation = async () => {
    const cas = await signer.call("nodeCaStates", {}, { result: caStates });
    const next = cas.find((c) => c.state === "next");
    const retiring = cas.find((c) => c.state === "retiring");
    const nodes = listNodes(db);
    const pending = next
      ? {
          step: "promote" as const,
          nodes: nodes.filter((n) => !n.trustedCas.includes(next.name)).map((n) => n.name),
        }
      : retiring
        ? {
            step: "finish" as const,
            nodes: nodes.filter((n) => n.ca === retiring.name).map((n) => n.name),
          }
        : null;
    return {
      cas: cas.map((c) => ({
        name: c.name,
        state: c.state,
        expires_at: new Date(c.notAfter).toISOString(),
      })),
      pending,
    };
  };

  return {
    nodeCaRotation: method(b.object({}), rotation),

    rotateNodeCa: method(
      b.object({ step: b.enum(["start", "promote", "finish"]) }),
      async ({ step }) => {
        const { pending } = await rotation();
        if (step === "start" && pending) {
          throw new RpcError(
            "invalid",
            `a CA rotation is in progress: next step is ${pending.step}`,
          );
        }
        if (step !== "start") {
          if (pending?.step !== step) {
            throw new RpcError(
              "invalid",
              pending ? `the next step is ${pending.step}` : "no CA rotation in progress",
            );
          }
          if (pending.nodes.length > 0) {
            const why =
              step === "promote"
                ? "do not trust the new CA yet"
                : "still have a certificate from the old CA";
            throw new RpcError("invalid", `${pending.nodes.join(", ")} ${why}`);
          }
        }
        const { dropped } = await signer.call(
          "rotateNodeCa",
          { step },
          { result: b.object({ cas: caStates, dropped: droppedCas }) },
        );
        await identity.reissue();
        await links.identityChanged();
        await deps.deliveryLink?.upkeep(true);
        log.info("node CA rotation step done", { step });
        return {
          ...(await rotation()),
          dropped: dropped.map((d) => ({ name: d.name, store_key: d.storeKey })),
        };
      },
    ),

    addNode: method(
      b.object({
        name: b.string().max(63),
        address: b.string().max(64),
        csr: b.string().max(4000),
        kind: b.enum(["delivery", "egress"]).default("delivery"),
      }),
      async ({ name, address, csr, kind }) => {
        if (!validName(name)) {
          throw new RpcError("invalid", "node names use a-z, 0-9 and -, up to 63 characters");
        }
        if (!parseLinkAddress(address))
          throw new RpcError("invalid", "use <ip>:<port> or [<ipv6>]:<port>, port 1024-65535");
        if (getNode(db, name)) throw new RpcError("invalid", `there is already a node ${name}`);
        const { cert, ca } = await signer.call(
          "issueNodeCertificate",
          { csr, purpose: "server", days: NODE_DAYS },
          { result: issued },
        );
        const { cert: parsed, ca: issuer, trustedCas } = trustOf(cert, ca);
        if (parsed.commonNames[0] !== name) {
          throw new RpcError("invalid", `the request is for ${parsed.commonNames[0]}, not ${name}`);
        }
        const node = {
          name,
          kind,
          address,
          pin: pinOf(parsed.spki),
          notAfter: parsed.notAfter,
          ca: issuer,
          trustedCas,
          corePins: [identity.current().pin],
          createdAt: now(),
        };
        if (!(await writer.run((d) => addNode(d, node)))) {
          throw new RpcError("invalid", `there is already a node ${name} or one at ${address}`);
        }
        links.sync();
        log.info(kind === "egress" ? "egress added" : "delivery node added", { name, address });
        return { name, kind, cert, ca, corePins: [identity.current().pin] };
      },
    ),

    listNodes: method(b.object({}), () => {
      const health = deps.health?.() ?? [];
      return listNodes(db).map((n) => {
        const h = health.find((x) => x.name === n.name);
        return {
          name: n.name,
          kind: n.kind,
          address: n.address,
          pin: n.pin,
          up: h?.up ?? false,
          last_seen_at: h?.lastSeen ? new Date(h.lastSeen).toISOString() : null,
          ips: h?.ips ?? [],
          certificate_expires_at: new Date(n.notAfter).toISOString(),
          created_at: new Date(n.createdAt).toISOString(),
        };
      });
    }),

    removeNode: method(b.object({ name: b.string().max(63) }), async ({ name }) => {
      if (!(await writer.run((d) => removeNode(d, name)))) {
        throw new RpcError("not-found", `no node ${name}`);
      }
      links.close(name);
      log.info("delivery node removed", { name });
      return { name, removed: true };
    }),
  };
}
