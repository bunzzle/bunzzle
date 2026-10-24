import { fromPem, pem } from "../asn1/der.ts";
import { type Methods, method, pinOf, RpcError } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { type Certificate, parseCertificate } from "../x509/cert.ts";
import { certificateRequest } from "../x509/issue.ts";
import { verifySignature } from "../x509/verify.ts";

export const DELIVERY_NAME = "delivery";

export interface DeliveryLink {
  cert: string;
  key: string;
  ca: string;
  pin: string;
  issuer: string;
  notAfter: number;
}

const same = (a: Uint8Array, c: Uint8Array) =>
  a.length === c.length && a.every((x, i) => x === c[i]);

export class DeliveryIdentity {
  #current: DeliveryLink | null = null;
  #pending: CryptoKeyPair | null = null;

  current(): DeliveryLink | null {
    return this.#current;
  }

  async request(): Promise<string> {
    this.#pending = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return (await certificateRequest(DELIVERY_NAME, this.#pending)).toBase64();
  }

  async install(certPem: string, caPem: string, now = Date.now()): Promise<DeliveryLink> {
    const key = this.#pending;
    if (!key) throw new RpcError("invalid", "no request in progress");
    const cert = parseCertificate(fromPem(certPem)[0] as Uint8Array);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
    if (!same(cert.spki, spki)) {
      throw new RpcError("invalid", "the certificate is not for the pending key");
    }
    if (cert.commonNames[0] !== DELIVERY_NAME) {
      throw new RpcError("invalid", `the certificate is for ${cert.commonNames[0]}`);
    }
    const cas = fromPem(caPem).map((d) => parseCertificate(d));
    const issuer: Certificate | undefined = cas.find((c) => same(c.subject, cert.issuer));
    if (!issuer || !(await verifySignature(cert, issuer.spki))) {
      throw new RpcError("invalid", "the certificate does not chain to the CA bundle");
    }
    if (cert.notAfter <= now) throw new RpcError("invalid", "the certificate expired");
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
    const keyPem = pem("PRIVATE KEY", pkcs8);
    pkcs8.fill(0);
    this.#current = {
      cert: certPem,
      key: keyPem,
      ca: caPem,
      pin: pinOf(cert.spki),
      issuer: issuer.commonNames[0] ?? "",
      notAfter: cert.notAfter,
    };
    this.#pending = null;
    return this.#current;
  }

  methods(): Methods {
    const view = () => {
      const c = this.#current;
      return c ? { pin: c.pin, issuer: c.issuer, notAfter: c.notAfter } : null;
    };
    return {
      linkIdentity: method(b.object({}), view),
      linkRequest: method(b.object({}), async () => ({ csr: await this.request() })),
      linkInstall: method(
        b.object({ cert: b.string().max(10_000), ca: b.string().max(20_000) }),
        async ({ cert, ca }) => {
          await this.install(cert, ca);
          return view();
        },
      ),
    };
  }
}
