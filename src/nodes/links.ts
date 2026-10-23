import type { Database } from "bun:sqlite";
import { fromPem } from "../asn1/der.ts";
import { parseLinkAddress } from "../config.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { type LinkTls, pinOf, RpcClient, RpcError } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import type { CoreIdentity } from "./identity.ts";
import type { NodeStatus } from "./node.ts";
import { type DeliveryNode, listNodes, updateNode } from "./registry.ts";

const DAY = 86_400_000;
const NODE_DAYS = 30;
const NODE_RENEW_MS = 10 * DAY;
const CORE_RENEW_MS = DAY;
const CORE_FORCE_MS = 2 * DAY;
const CALL_MS = 30_000;

const status = b.object({
  name: b.string(),
  cas: b.array(b.string()),
  corePins: b.array(b.string()),
  pin: b.string(),
  issuer: b.string(),
  notAfter: b.number(),
});
const issued = b.object({ cert: b.string(), ca: b.string() });
const caStates = b.array(
  b.object({
    name: b.string(),
    state: b.enum(["active", "next", "retiring"]),
    notAfter: b.number(),
  }),
);

const sameSet = (a: string[], c: string[]) =>
  a.length === c.length && a.every((x) => c.includes(x));

interface Link {
  tls: LinkTls;
  client: RpcClient;
}

export interface LinkDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  identity: CoreIdentity;
  now?: () => number;
}

export class NodeLinks {
  readonly #d: LinkDeps;
  readonly #now: () => number;
  readonly #links = new Map<string, Link>();
  #handoff: string[] = [];

  constructor(deps: LinkDeps) {
    this.#d = deps;
    this.#now = deps.now ?? Date.now;
  }

  #open(node: DeliveryNode): Link {
    const at = parseLinkAddress(node.address);
    if (!at) throw new RpcError("invalid", `bad address for ${node.name}`);
    const me = this.#d.identity.current();
    const tls: LinkTls = {
      cert: me.cert,
      key: me.key,
      ca: me.ca,
      pins: [node.pin],
      name: node.name,
    };
    return { tls, client: new RpcClient({ ...at, tls }) };
  }

  sync(): void {
    const nodes = listNodes(this.#d.db);
    for (const n of nodes) if (!this.#links.has(n.name)) this.#links.set(n.name, this.#open(n));
    for (const name of [...this.#links.keys()]) {
      if (!nodes.some((n) => n.name === name)) this.close(name);
    }
  }

  close(name: string): void {
    const link = this.#links.get(name);
    if (!link) return;
    this.#links.delete(name);
    link.client.close();
  }

  closeAll(): void {
    for (const name of [...this.#links.keys()]) this.close(name);
  }

  names(): string[] {
    return [...this.#links.keys()].sort();
  }

  client(name: string): RpcClient | null {
    return this.#links.get(name)?.client ?? null;
  }

  #call<R>(link: Link, method: string, params: unknown, result: b.Schema<R>): Promise<R> {
    return link.client.call(method, params, { result, timeoutMs: CALL_MS });
  }

  #refreshIdentity(): void {
    const me = this.#d.identity.current();
    for (const link of this.#links.values()) {
      Object.assign(link.tls, { cert: me.cert, key: me.key, ca: me.ca });
      link.client.close();
    }
  }

  #corePins(): string[] {
    return [this.#d.identity.current().pin, ...this.#handoff];
  }

  async #save(name: string, st: NodeStatus): Promise<void> {
    await this.#d.writer.run((w) =>
      updateNode(w, name, {
        pin: st.pin,
        notAfter: st.notAfter,
        ca: st.issuer,
        trustedCas: st.cas,
        corePins: st.corePins,
      }),
    );
  }

  async #renewNode(name: string, link: Link): Promise<NodeStatus> {
    const { csr } = await this.#call(link, "renewRequest", {}, b.object({ csr: b.string() }));
    const { cert, ca } = await this.#d.signer.call(
      "issueNodeCertificate",
      { csr, purpose: "server", days: NODE_DAYS },
      { result: issued },
    );
    const parsed = parseCertificate(fromPem(cert)[0] as Uint8Array);
    if (parsed.commonNames[0] !== name) {
      throw new RpcError("invalid", `${name} asked for a certificate for ${parsed.commonNames[0]}`);
    }
    const installed = await this.#call(link, "renewInstall", { cert, ca }, status);
    await this.#save(name, installed);
    link.tls.pins.splice(0, link.tls.pins.length, pinOf(parsed.spki));
    link.client.close();
    const st = await this.#call(link, "linkStatus", {}, status);
    this.#d.log.info("node certificate renewed", { name, issuer: st.issuer });
    return st;
  }

  async reconcile(name: string): Promise<NodeStatus> {
    const link = this.#links.get(name);
    if (!link) throw new RpcError("not-found", `no node ${name}`);
    let st = await this.#call(link, "linkStatus", {}, status);
    if (st.name !== name) throw new RpcError("invalid", `${name} answers as ${st.name}`);
    const trusted = await this.#d.signer.call("nodeCa", {}, { result: b.string() });
    const cas = fromPem(trusted).map((d) => parseCertificate(d).commonNames[0] ?? "");
    if (!sameSet(st.cas, cas)) st = await this.#call(link, "trustCas", { ca: trusted }, status);
    const pins = this.#corePins();
    if (!sameSet(st.corePins, pins)) st = await this.#call(link, "trustCorePins", { pins }, status);
    const states = await this.#d.signer.call("nodeCaStates", {}, { result: caStates });
    const active = states.find((c) => c.state === "active")?.name;
    if (st.issuer !== active || st.notAfter - this.#now() < NODE_RENEW_MS) {
      st = await this.#renewNode(name, link);
    }
    await this.#save(name, st);
    return st;
  }

  async reconcileAll(): Promise<{ name: string; error: string | null }[]> {
    this.sync();
    return Promise.all(
      this.names().map(async (name) => {
        try {
          await this.reconcile(name);
          return { name, error: null };
        } catch (err) {
          const error = (err as Error).message;
          this.#d.log.warn("node link check failed", { name, error });
          return { name, error };
        }
      }),
    );
  }

  coreRenewalDue(): boolean {
    const issuedFor = 7 * DAY;
    const age = this.#now() - (this.#d.identity.current().notAfter - issuedFor);
    return age >= CORE_RENEW_MS;
  }

  async renewCore(): Promise<boolean> {
    this.sync();
    const current = this.#d.identity.current();
    const links = [...this.#links.entries()];
    try {
      await this.#d.identity.renew(async (next) => {
        this.#handoff = [next.pin];
        const results = await Promise.allSettled(
          links.map(([, l]) =>
            this.#call(l, "trustCorePins", { pins: [current.pin, next.pin] }, status),
          ),
        );
        const missed = links.filter((_, i) => results[i]?.status === "rejected").map(([n]) => n);
        if (missed.length === 0) return;
        if (current.notAfter - this.#now() > CORE_FORCE_MS) {
          throw new RpcError("unavailable", `nodes not reachable: ${missed.join(", ")}`);
        }
        this.#d.log.warn("core certificate renewed while nodes were not reachable", {
          nodes: missed,
        });
      });
    } catch (err) {
      this.#handoff = [];
      this.#d.log.warn("core certificate not renewed", { error: (err as Error).message });
      return false;
    }
    this.#handoff = [];
    this.#refreshIdentity();
    await this.reconcileAll();
    this.#d.log.info("core certificate renewed", { pin: this.#d.identity.current().pin });
    return true;
  }

  async identityChanged(): Promise<void> {
    this.#refreshIdentity();
    await this.reconcileAll();
  }
}
