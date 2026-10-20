import { describe, expect, test } from "bun:test";
import { Desec } from "../../src/net/desec.ts";
import { txtText, txtValue } from "../../src/net/rdata.ts";
import type { RequestInput, RequestResult } from "../../src/net/request.ts";

const BASE = "https://desec.test/api/v1";

interface FakeSet {
  ttl: number;
  records: string[];
}

class FakeDesec {
  readonly domains = ["example.test", "sub.example.test", "examples.test"];
  readonly sets = new Map<string, FakeSet>();
  readonly writes: { method: string; path: string; body: unknown }[] = [];
  readonly slept: number[] = [];
  throttle: string[] = [];
  beforeWrite: (() => void) | null = null;

  #json(status: number, body: unknown): RequestResult {
    return {
      ok: true,
      status,
      headers: new Map(),
      body: body === undefined ? "" : JSON.stringify(body),
    };
  }

  #owner(qname: string): string | undefined {
    return this.domains
      .filter((d) => qname === d || qname.endsWith(`.${d}`))
      .sort((a, b) => b.length - a.length)[0];
  }

  #valid(type: string, records: unknown): string | null {
    if (!Array.isArray(records)) return "records must be a list";
    for (const r of records) {
      if (typeof r !== "string") return "records must be strings";
      if (type === "TXT" && !/^"(?:[^"\\]|\\.){0,255}"(?: "(?:[^"\\]|\\.){0,255}")*$/.test(r)) {
        return `invalid TXT content ${r}`;
      }
      if (type === "MX" && !/^\d+ \S+\.$/.test(r)) return `invalid MX content ${r}`;
    }
    return null;
  }

  sleep = async (ms: number) => {
    this.slept.push(ms);
  };

  request = async (r: RequestInput): Promise<RequestResult> => {
    if (r.headers?.["Authorization"] !== "Token secret-token") {
      return this.#json(401, { detail: "Invalid token." });
    }
    const wait = this.throttle.shift();
    if (wait !== undefined) {
      return {
        ok: true,
        status: 429,
        headers: new Map([["retry-after", wait]]),
        body: JSON.stringify({ detail: "Request was throttled." }),
      };
    }
    const u = new URL(r.url);
    const path = u.pathname.replace(/^\/api\/v1/, "");
    if (path === "/domains/" && r.method === "GET") {
      const owner = this.#owner(u.searchParams.get("owns_qname") ?? "");
      return this.#json(200, owner ? [{ name: owner }] : []);
    }
    const one = /^\/domains\/([^/]+)\/rrsets\/([^/]+)\/([A-Z]+)\/$/.exec(path);
    if (one) {
      const [, domain, sub, type] = one as unknown as [string, string, string, string];
      if (!this.domains.includes(domain)) return this.#json(404, { detail: "Not found." });
      const key = `${domain}|${sub === "@" ? "" : sub}|${type}`;
      const set = this.sets.get(key);
      if (r.method === "GET") {
        return set
          ? this.#json(200, { subname: sub === "@" ? "" : sub, type, ...set })
          : this.#json(404, { detail: "Not found." });
      }
      if (r.method === "PATCH") {
        this.beforeWrite?.();
        if (!set || !this.sets.has(key)) return this.#json(404, { detail: "Not found." });
        const body = JSON.parse(r.body ?? "{}") as { records: unknown };
        this.writes.push({ method: "PATCH", path, body });
        const bad = this.#valid(type, body.records);
        if (bad) return this.#json(400, { records: [bad] });
        if ((body.records as string[]).length === 0) {
          this.sets.delete(key);
          return this.#json(204, undefined);
        }
        set.records = body.records as string[];
        return this.#json(200, { subname: sub === "@" ? "" : sub, type, ...set });
      }
    }
    const list = /^\/domains\/([^/]+)\/rrsets\/$/.exec(path);
    if (list && r.method === "POST") {
      const domain = list[1] as string;
      const body = JSON.parse(r.body ?? "{}") as {
        subname: string;
        type: string;
        ttl: number;
        records: unknown;
      };
      this.writes.push({ method: "POST", path, body });
      if (body.subname === "@") return this.#json(400, { subname: ["Invalid subname."] });
      if (body.ttl < 3600) {
        return this.#json(400, { ttl: ["Ensure this value is greater than or equal to 3600."] });
      }
      const bad = this.#valid(body.type, body.records);
      if (bad) return this.#json(400, { records: [bad] });
      const key = `${domain}|${body.subname}|${body.type}`;
      if (this.sets.has(key)) {
        return this.#json(400, {
          non_field_errors: [
            "Another RRset with the same subdomain and type exists for this domain.",
          ],
        });
      }
      this.sets.set(key, { ttl: body.ttl, records: body.records as string[] });
      return this.#json(201, { ...body });
    }
    return this.#json(404, { detail: "Not found." });
  };
}

const setup = () => {
  const fake = new FakeDesec();
  return { fake, desec: new Desec("secret-token", BASE, fake.request, fake.sleep) };
};

const dkim = (key: string) => `v=DKIM1; k=rsa; p=${key}${"A".repeat(380)}`;

describe("deSEC", () => {
  test("finds the domain that owns a name, deepest first", async () => {
    const { desec } = setup();
    expect(await desec.zoneFor("bunzzle._domainkey.example.test.")).toBe("example.test");
    expect(await desec.zoneFor("mail.sub.example.test")).toBe("sub.example.test");
    expect(await desec.zoneFor("EXAMPLE.test")).toBe("example.test");
    expect(await desec.zoneFor("nothing.invalid")).toBeNull();
  });

  test("creates a long TXT record split into quoted strings with the minimum TTL", async () => {
    const { fake, desec } = setup();
    const rec = {
      type: "TXT" as const,
      name: "bunzzle._domainkey.example.test",
      content: dkim("K"),
    };
    expect(await desec.upsert(rec)).toEqual({ ok: true, action: "created" });
    const set = fake.sets.get("example.test|bunzzle._domainkey|TXT");
    expect(set?.ttl).toBe(3600);
    expect(set?.records).toHaveLength(1);
    expect(set?.records[0]).toBe(txtValue(rec.content));
    expect((set?.records[0] ?? "").split('" "')).toHaveLength(2);
    expect(set?.records.map(txtText)).toEqual([rec.content]);
    expect(await desec.upsert(rec)).toEqual({ ok: true, action: "exists" });
    expect(fake.writes).toHaveLength(1);
  });

  test("uses @ in the path and an empty subname in the body at the apex", async () => {
    const { fake, desec } = setup();
    const mx = {
      type: "MX" as const,
      name: "example.test",
      content: "mx.example.test",
      priority: 5,
    };
    expect(await desec.upsert(mx)).toEqual({ ok: true, action: "created" });
    expect(fake.writes[0]?.body).toMatchObject({ subname: "", type: "MX" });
    expect(fake.sets.get("example.test||MX")?.records).toEqual(["5 mx.example.test."]);
    expect(await desec.upsert({ ...mx, name: "example.test." })).toEqual({
      ok: true,
      action: "exists",
    });
    const spf = { type: "TXT" as const, name: "example.test", content: "v=spf1 a -all" };
    fake.sets.set("example.test||TXT", {
      ttl: 3600,
      records: ['"v=spf1 -all"', '"google-site-verification=x"'],
    });
    expect(await desec.upsert(spf)).toEqual({ ok: true, action: "updated" });
    expect(fake.writes.at(-1)?.path).toBe("/domains/example.test/rrsets/@/TXT/");
    expect(fake.sets.get("example.test||TXT")?.records).toEqual([
      '"v=spf1 a -all"',
      '"google-site-verification=x"',
    ]);
  });

  test("replaces only Bunzzle's DKIM value and keeps the rest of the RRset", async () => {
    const { fake, desec } = setup();
    fake.sets.set("example.test|bunzzle._domainkey|TXT", {
      ttl: 7200,
      records: [txtValue(dkim("OLD")), '"someone-else"'],
    });
    const rec = {
      type: "TXT" as const,
      name: "bunzzle._domainkey.example.test",
      content: dkim("NEW"),
    };
    expect(await desec.upsert(rec)).toEqual({ ok: true, action: "updated" });
    expect(fake.sets.get("example.test|bunzzle._domainkey|TXT")).toEqual({
      ttl: 7200,
      records: [txtValue(dkim("NEW")), '"someone-else"'],
    });
  });

  test("removes one value, and the whole RRset when it was the last", async () => {
    const { fake, desec } = setup();
    fake.sets.set("example.test|_acme-challenge.mail|TXT", {
      ttl: 3600,
      records: ['"token-a"', '"token-b"'],
    });
    const a = {
      type: "TXT" as const,
      name: "_acme-challenge.mail.example.test",
      content: "token-a",
    };
    expect(await desec.remove(a)).toEqual({ ok: true, action: "removed" });
    expect(fake.sets.get("example.test|_acme-challenge.mail|TXT")?.records).toEqual(['"token-b"']);
    expect(await desec.remove(a)).toEqual({ ok: true, action: "absent" });
    expect(await desec.remove({ ...a, content: "token-b" })).toEqual({
      ok: true,
      action: "removed",
    });
    expect(fake.sets.has("example.test|_acme-challenge.mail|TXT")).toBe(false);
    expect(await desec.remove({ ...a, content: "token-b" })).toEqual({
      ok: true,
      action: "absent",
    });
  });

  test("fails when the RRset disappears between the read and the write", async () => {
    const { fake, desec } = setup();
    fake.sets.set("example.test||TXT", { ttl: 3600, records: ['"v=spf1 -all"'] });
    fake.beforeWrite = () => fake.sets.delete("example.test||TXT");
    expect(
      await desec.upsert({ type: "TXT", name: "example.test", content: "v=spf1 a -all" }),
    ).toEqual({ ok: false, error: "deSEC: Not found." });
  });

  test("waits for Retry-After when throttled, and gives up on long waits", async () => {
    const { fake, desec } = setup();
    fake.throttle = ["2", "0"];
    const rec = { type: "TXT" as const, name: "example.test", content: "v=spf1 -all" };
    expect(await desec.upsert(rec)).toEqual({ ok: true, action: "created" });
    expect(fake.slept).toEqual([2_000, 1_000]);
    fake.throttle = ["3600"];
    expect(await desec.remove(rec)).toEqual({ ok: false, error: "deSEC: Request was throttled." });
    fake.throttle = ["1", "1", "1"];
    expect(await desec.remove(rec)).toEqual({ ok: false, error: "deSEC: Request was throttled." });
  });

  test("reports API errors and missing domains", async () => {
    const { fake, desec } = setup();
    expect(
      await desec.upsert({ type: "TXT", name: "x.nothing.invalid", content: "v=spf1 -all" }),
    ).toEqual({ ok: false, error: "no deSEC domain for x.nothing.invalid" });
    const wrong = new Desec("wrong", BASE, fake.request, fake.sleep);
    expect(await wrong.upsert({ type: "TXT", name: "example.test", content: "v" })).toEqual({
      ok: false,
      error: "deSEC: Invalid token.",
    });
    const down = new Desec("secret-token", BASE, async () => ({ ok: false, error: "refused" }));
    expect(await down.upsert({ type: "TXT", name: "example.test", content: "v" })).toEqual({
      ok: false,
      error: "refused",
    });
  });
});
