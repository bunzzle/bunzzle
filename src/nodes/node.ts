import { fromPem, pem } from "../asn1/der.ts";
import { type LinkTls, type Methods, method, pinOf, RpcError, type RpcServer } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { type Certificate, parseCertificate } from "../x509/cert.ts";
import { certificateRequest } from "../x509/issue.ts";
import { verifySignature } from "../x509/verify.ts";

const PIN = /^sha256\/[A-Za-z0-9+/]{43}=$/;

export interface NodeStatus {
  name: string;
  cas: string[];
  corePins: string[];
  deliveryPins: string[];
  pin: string;
  issuer: string;
  notAfter: number;
}

const same = (a: Uint8Array, c: Uint8Array) =>
  a.length === c.length && a.every((x, i) => x === c[i]);

const certOf = (text: string) => parseCertificate(fromPem(text)[0] as Uint8Array);
const casOf = (text: string) => fromPem(text).map((d) => parseCertificate(d));

function issuerOf(cert: Certificate, cas: Certificate[]): Certificate | null {
  return cas.find((c) => same(c.subject, cert.issuer)) ?? null;
}

async function writeAtomic(path: string, text: string, mode = "644") {
  const tmp = `${path}.${crypto.randomUUID()}.tmp`;
  await Bun.write(tmp, text);
  await Bun.$`chmod ${mode} ${tmp} && mv -f ${tmp} ${path}`.quiet();
}

export interface Peers {
  core: string[];
  delivery: string[];
}

export function statusOf(tls: LinkTls, peers: Peers): NodeStatus {
  const cert = certOf(tls.cert);
  const cas = casOf(tls.ca);
  return {
    name: cert.commonNames[0] ?? "",
    cas: cas.map((c) => c.commonNames[0] ?? ""),
    corePins: [...peers.core],
    deliveryPins: [...peers.delivery],
    pin: pinOf(cert.spki),
    issuer: issuerOf(cert, cas)?.commonNames[0] ?? "",
    notAfter: cert.notAfter,
  };
}

export function nodeLinkMethods(
  dir: string,
  tls: LinkTls,
  server: () => RpcServer,
  peers: Peers = { core: [...tls.pins], delivery: [] },
): Methods {
  let pending: CryptoKeyPair | null = null;
  const accept = () => tls.pins.splice(0, tls.pins.length, ...peers.core, ...peers.delivery);
  const status = () => statusOf(tls, peers);

  const reload = (next: LinkTls) => {
    server().reload(next);
    Object.assign(tls, next, { pins: tls.pins });
  };

  return {
    linkStatus: method(b.object({}), status),

    trustCorePins: method(
      b.object({ pins: b.array(b.string()).min(1).max(4) }),
      async ({ pins }) => {
        if (!pins.every((p) => PIN.test(p))) throw new RpcError("invalid", "bad pin");
        await writeAtomic(`${dir}/peer.pin`, `${pins.join("\n")}\n`);
        peers.core = [...pins];
        accept();
        return status();
      },
    ),

    trustDeliveryPins: method(b.object({ pins: b.array(b.string()).max(2) }), async ({ pins }) => {
      if (!pins.every((p) => PIN.test(p))) throw new RpcError("invalid", "bad pin");
      await writeAtomic(`${dir}/delivery.pin`, pins.length ? `${pins.join("\n")}\n` : "");
      peers.delivery = [...pins];
      accept();
      return status();
    }),

    trustCas: method(b.object({ ca: b.string().max(20_000) }), async ({ ca }) => {
      const cas = casOf(ca);
      if (cas.length === 0 || !cas.every((c) => c.ca)) {
        throw new RpcError("invalid", "not a CA bundle");
      }
      if (!issuerOf(certOf(tls.cert), cas)) {
        throw new RpcError("invalid", "the bundle does not hold the CA of this node's certificate");
      }
      await writeAtomic(`${dir}/ca.pem`, ca);
      reload({ ...tls, ca });
      return status();
    }),

    renewRequest: method(b.object({}), async () => {
      pending = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      const name = certOf(tls.cert).commonNames[0] ?? "";
      return { csr: (await certificateRequest(name, pending)).toBase64() };
    }),

    renewInstall: method(
      b.object({ cert: b.string().max(10_000), ca: b.string().max(20_000) }),
      async (p) => {
        const key = pending;
        if (!key) throw new RpcError("invalid", "no renewal in progress");
        const cert = certOf(p.cert);
        const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
        if (!same(cert.spki, spki)) {
          throw new RpcError("invalid", "the certificate is not for the pending key");
        }
        const issuer = issuerOf(cert, casOf(p.ca));
        if (!issuer || !(await verifySignature(cert, issuer.spki))) {
          throw new RpcError("invalid", "the certificate does not chain to the CA bundle");
        }
        if (cert.notAfter <= Date.now()) throw new RpcError("invalid", "the certificate expired");
        const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
        const keyPem = pem("PRIVATE KEY", pkcs8);
        pkcs8.fill(0);
        const next = { ...tls, cert: p.cert, key: keyPem, ca: p.ca };
        reload(next);
        const id = crypto.randomUUID();
        const files = [
          ["key.pem", keyPem, "600"],
          ["cert.pem", p.cert, "644"],
          ["ca.pem", p.ca, "644"],
        ] as const;
        for (const [name, text, mode] of files) {
          await Bun.write(`${dir}/${name}.${id}.tmp`, text);
          await Bun.$`chmod ${mode} ${dir}/${name}.${id}.tmp`.quiet();
        }
        await Bun.$`mv -f ${dir}/key.pem.${id}.tmp ${dir}/key.pem && mv -f ${dir}/cert.pem.${id}.tmp ${dir}/cert.pem && mv -f ${dir}/ca.pem.${id}.tmp ${dir}/ca.pem`.quiet();
        pending = null;
        return status();
      },
    ),
  };
}
