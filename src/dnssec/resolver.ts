import { DNSSEC_PROBE } from "../dns/dnssec.ts";
import { answerFrom, type Resolver } from "../dns/resolver.ts";
import { normalizeName, Rcode, RRType } from "../dns/wire.ts";
import { type Fetch, Validator } from "./validator.ts";

export function validatingResolver(validator: Validator): Resolver {
  return {
    async query(rawName, type) {
      const name = normalizeName(rawName);
      const r = await validator.validate(name, RRType[type]);
      if (r.status === "bogus") {
        return {
          name,
          type,
          rcode: Rcode.SERVFAIL,
          authenticated: false,
          records: [],
          ttl: 0,
          bogus: r.reason ?? "bogus",
        };
      }
      return { ...answerFrom(r.message, name, type), authenticated: r.status === "secure" };
    },
  };
}

export async function ownValidation(
  fetch: Fetch,
  o: { probe?: string; anchors?: ConstructorParameters<typeof Validator>[0]["anchors"] } = {},
): Promise<{ resolver: Resolver } | { problem: string }> {
  const validator = new Validator({ fetch, ...(o.anchors ? { anchors: o.anchors } : {}) });
  const probe = await validator.validate(o.probe ?? DNSSEC_PROBE, RRType.A);
  if (probe.status !== "secure") {
    return {
      problem: `the DNS servers do not return what DNSSEC needs (${o.probe ?? DNSSEC_PROBE}: ${probe.status}${probe.reason ? `, ${probe.reason}` : ""})`,
    };
  }
  return { resolver: validatingResolver(validator) };
}
