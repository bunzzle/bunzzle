import { fromPem } from "../asn1/der.ts";
import type { Logger } from "../core/log.ts";
import { pinOf, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import { DELIVERY_NAME } from "./delivery-identity.ts";
import type { NodeLinks } from "./links.ts";

const DAY = 86_400_000;
const DELIVERY_DAYS = 7;
const RENEW_AFTER_MS = DAY;
const FORCE_MS = 2 * DAY;
const CALL_MS = 30_000;

const identity = b.object({ pin: b.string(), issuer: b.string(), notAfter: b.number() }).nullable();
const issued = b.object({ cert: b.string(), ca: b.string() });
const caStates = b.array(
  b.object({
    name: b.string(),
    state: b.enum(["active", "next", "retiring"]),
    notAfter: b.number(),
  }),
);

export interface DeliveryLinkDeps {
  delivery: RpcClient;
  signer: RpcClient;
  links: NodeLinks;
  log: Logger;
  now?: () => number;
}

export class DeliveryLinkKeeper {
  readonly #d: DeliveryLinkDeps;
  readonly #now: () => number;
  #current: { pin: string; notAfter: number } | null = null;
  #next: string | null = null;
  #known = false;

  constructor(deps: DeliveryLinkDeps) {
    this.#d = deps;
    this.#now = deps.now ?? Date.now;
  }

  pins(): string[] | null {
    if (!this.#known) return null;
    return [...(this.#current ? [this.#current.pin] : []), ...(this.#next ? [this.#next] : [])];
  }

  notAfter(): number | null {
    return this.#current?.notAfter ?? null;
  }

  async upkeep(force = false): Promise<boolean> {
    const id = await this.#d.delivery.call(
      "linkIdentity",
      {},
      { result: identity, timeoutMs: CALL_MS },
    );
    this.#current = id ? { pin: id.pin, notAfter: id.notAfter } : null;
    this.#known = true;
    const states = await this.#d.signer.call("nodeCaStates", {}, { result: caStates });
    const active = states.find((c) => c.state === "active")?.name;
    const due =
      !id ||
      id.issuer !== active ||
      id.notAfter <= this.#now() ||
      this.#now() - (id.notAfter - DELIVERY_DAYS * DAY) >= RENEW_AFTER_MS;
    if (!force && !due) return false;
    return this.#renew();
  }

  async #renew(): Promise<boolean> {
    const { csr } = await this.#d.delivery.call(
      "linkRequest",
      {},
      { result: b.object({ csr: b.string() }), timeoutMs: CALL_MS },
    );
    const { cert, ca } = await this.#d.signer.call(
      "issueNodeCertificate",
      { csr, purpose: "client", days: DELIVERY_DAYS },
      { result: issued },
    );
    const parsed = parseCertificate(fromPem(cert)[0] as Uint8Array);
    if (parsed.commonNames[0] !== DELIVERY_NAME) {
      throw new RpcError(
        "invalid",
        `delivery asked for a certificate for ${parsed.commonNames[0]}`,
      );
    }
    const current = this.#current;
    this.#next = pinOf(parsed.spki);
    const missed = await this.#d.links.pushDeliveryPins(this.pins() ?? []);
    const valid = current !== null && current.notAfter - this.#now() > FORCE_MS;
    if (missed.length > 0 && valid) {
      this.#next = null;
      await this.#d.links.pushDeliveryPins(this.pins() ?? []);
      this.#d.log.warn("delivery link certificate not renewed", {
        error: `egresses not reachable: ${missed.join(", ")}`,
      });
      return false;
    }
    if (missed.length > 0) {
      this.#d.log.warn("delivery link certificate renewed while egresses were not reachable", {
        egresses: missed,
      });
    }
    const installed = await this.#d.delivery.call(
      "linkInstall",
      { cert, ca },
      { result: identity, timeoutMs: CALL_MS },
    );
    this.#current = installed ? { pin: installed.pin, notAfter: installed.notAfter } : null;
    this.#next = null;
    await this.#d.links.pushDeliveryPins(this.pins() ?? []);
    this.#d.log.info("delivery link certificate renewed", { pin: this.#current?.pin });
    return true;
  }
}
