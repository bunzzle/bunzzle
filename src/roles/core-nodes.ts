import type { Database } from "bun:sqlite";
import { fromPem } from "../asn1/der.ts";
import { parseLinkAddress } from "../config.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { type Methods, method, pinOf, type RpcClient, RpcError } from "../ipc/rpc.ts";
import type { CoreIdentity } from "../nodes/identity.ts";
import { addNode, getNode, listNodes, removeNode } from "../nodes/registry.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import { validName } from "../x509/issue.ts";

const NODE_DAYS = 30;
const issued = b.object({ cert: b.string(), ca: b.string() });

export interface NodeDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  identity: CoreIdentity;
  now?: () => number;
}

export function nodeMethods(deps: NodeDeps): Methods {
  const { db, writer, log, signer, identity } = deps;
  const now = deps.now ?? Date.now;

  return {
    addNode: method(
      b.object({
        name: b.string().max(63),
        address: b.string().max(64),
        csr: b.string().max(4000),
      }),
      async ({ name, address, csr }) => {
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
        const parsed = parseCertificate(fromPem(cert)[0] as Uint8Array);
        if (parsed.commonNames[0] !== name) {
          throw new RpcError("invalid", `the request is for ${parsed.commonNames[0]}, not ${name}`);
        }
        const node = {
          name,
          address,
          pin: pinOf(parsed.spki),
          notAfter: parsed.notAfter,
          createdAt: now(),
        };
        if (!(await writer.run((d) => addNode(d, node)))) {
          throw new RpcError("invalid", `there is already a node ${name} or one at ${address}`);
        }
        log.info("delivery node added", { name, address });
        return { name, cert, ca, corePins: [identity.current().pin] };
      },
    ),

    listNodes: method(b.object({}), () =>
      listNodes(db).map((n) => ({
        name: n.name,
        address: n.address,
        pin: n.pin,
        certificate_expires_at: new Date(n.notAfter).toISOString(),
        created_at: new Date(n.createdAt).toISOString(),
      })),
    ),

    removeNode: method(b.object({ name: b.string().max(63) }), async ({ name }) => {
      if (!(await writer.run((d) => removeNode(d, name)))) {
        throw new RpcError("not-found", `no node ${name}`);
      }
      log.info("delivery node removed", { name });
      return { name, removed: true };
    }),
  };
}
