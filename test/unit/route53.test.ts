import { describe, expect, test } from "bun:test";
import { child, children, parseXml, textAt } from "../../src/dmarc/xml.ts";
import type { RequestInput, RequestResult } from "../../src/net/request.ts";
import { Route53, txtText, txtValue } from "../../src/net/route53.ts";
import { signRequest } from "../../src/net/sigv4.ts";

const EXAMPLE = {
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
};
const AT = Date.parse("2015-08-30T12:36:00Z");
const BASE = "https://route53.test";

interface FakeSet {
  ttl: number;
  values: string[];
  alias?: boolean;
}

class FakeRoute53 {
  readonly zones = [
    { id: "ZOTHER", name: "example.test.", private: true },
    { id: "Z1", name: "example.test.", private: false },
    { id: "Z2", name: "examples.test.", private: false },
  ];
  readonly sets = new Map<string, FakeSet>();
  readonly posts: string[] = [];
  readonly failures: string[] = [];
  beforeChange: (() => void) | null = null;
  #changes = 0;
  #polled = new Set<string>();

  #error(status: number, code: string, message: string): RequestResult {
    return {
      ok: true,
      status,
      headers: new Map(),
      body: `<?xml version="1.0"?><ErrorResponse><Error><Type>Sender</Type><Code>${code}</Code><Message>${message}</Message></Error></ErrorResponse>`,
    };
  }

  #ok(body: string): RequestResult {
    return { ok: true, status: 200, headers: new Map(), body: `<?xml version="1.0"?>${body}` };
  }

  request = async (r: RequestInput): Promise<RequestResult> => {
    const auth = r.headers?.["Authorization"] ?? "";
    if (
      !/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/us-east-1\/route53\/aws4_request, /.test(
        auth,
      )
    ) {
      return this.#error(403, "SignatureDoesNotMatch", "The request signature is wrong");
    }
    const u = new URL(r.url);
    const path = u.pathname.replace(/^\/2013-04-01/, "");
    if (path === "/hostedzonesbyname") {
      const zones = this.zones
        .map(
          (z) =>
            `<HostedZone><Id>/hostedzone/${z.id}</Id><Name>${z.name}</Name><Config><PrivateZone>${z.private}</PrivateZone></Config></HostedZone>`,
        )
        .join("");
      return this.#ok(
        `<ListHostedZonesByNameResponse><HostedZones>${zones}</HostedZones></ListHostedZonesByNameResponse>`,
      );
    }
    const rrset = /^\/hostedzone\/Z1\/rrset\/?$/.exec(path);
    if (rrset && r.method === "GET") {
      const key = `${u.searchParams.get("name")}|${u.searchParams.get("type")}`;
      const found = this.sets.has(key) ? key : [...this.sets.keys()].sort().find((k) => k > key);
      const set = found ? this.sets.get(found) : undefined;
      const [name, type] = (found ?? "").split("|");
      const body = set
        ? `<ResourceRecordSet><Name>${name}</Name><Type>${type}</Type>${
            set.alias
              ? "<AliasTarget><DNSName>elsewhere.test.</DNSName></AliasTarget>"
              : `<TTL>${set.ttl}</TTL><ResourceRecords>${set.values
                  .map(
                    (v) =>
                      `<ResourceRecord><Value>${v.replace(/&/g, "&amp;")}</Value></ResourceRecord>`,
                  )
                  .join("")}</ResourceRecords>`
          }</ResourceRecordSet>`
        : "";
      return this.#ok(
        `<ListResourceRecordSetsResponse><ResourceRecordSets>${body}</ResourceRecordSets></ListResourceRecordSetsResponse>`,
      );
    }
    if (rrset && r.method === "POST") {
      this.beforeChange?.();
      const failure = this.failures.shift();
      if (failure) return this.#error(400, failure, "try again");
      this.posts.push(r.body ?? "");
      const changes = children(
        child(child(parseXml(r.body ?? "").children[0], "ChangeBatch"), "Changes"),
        "Change",
      );
      const next = new Map(this.sets);
      for (const c of changes) {
        const s = child(c, "ResourceRecordSet");
        const key = `${textAt(s, "Name")}|${textAt(s, "Type")}`;
        const set = {
          ttl: Number(textAt(s, "TTL")),
          values: children(child(s, "ResourceRecords"), "ResourceRecord").map(
            (x) => textAt(x, "Value") ?? "",
          ),
        };
        const current = next.get(key);
        if (textAt(c, "Action") === "DELETE") {
          if (!current || JSON.stringify(current) !== JSON.stringify(set)) {
            return {
              ok: true,
              status: 400,
              headers: new Map(),
              body: `<InvalidChangeBatch><Messages><Message>Tried to delete ${key} but the values do not match</Message></Messages></InvalidChangeBatch>`,
            };
          }
          next.delete(key);
        } else {
          if (current) return this.#error(400, "InvalidChangeBatch", `${key} already exists`);
          next.set(key, set);
        }
      }
      for (const [k, v] of next) this.sets.set(k, v);
      for (const k of [...this.sets.keys()]) if (!next.has(k)) this.sets.delete(k);
      const id = `C${++this.#changes}`;
      return this.#ok(
        `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/${id}</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`,
      );
    }
    const change = /^\/change\/(\w+)$/.exec(path);
    if (change) {
      const id = change[1] as string;
      const status = this.#polled.has(id) ? "INSYNC" : "PENDING";
      this.#polled.add(id);
      return this.#ok(
        `<GetChangeResponse><ChangeInfo><Id>/change/${id}</Id><Status>${status}</Status></ChangeInfo></GetChangeResponse>`,
      );
    }
    return this.#error(404, "NoSuchHostedZone", `no route for ${r.method} ${path}`);
  };
}

function setup() {
  const api = new FakeRoute53();
  const sleeps: number[] = [];
  const r53 = new Route53(
    EXAMPLE,
    BASE,
    api.request,
    () => AT,
    async (ms) => {
      sleeps.push(ms);
    },
  );
  return { api, r53, sleeps };
}

const dkim = (p: string) => `v=DKIM1; k=rsa; p=${p}`;

describe("signature version 4", () => {
  test("matches the published test vectors", async () => {
    const vanilla = await signRequest(
      { method: "GET", url: "https://example.amazonaws.com/" },
      EXAMPLE,
      { region: "us-east-1", service: "service" },
      AT,
    );
    expect(vanilla).toEqual({
      "x-amz-date": "20150830T123600Z",
      Authorization:
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    });
    const iam = await signRequest(
      {
        method: "GET",
        url: "https://iam.amazonaws.com/?Version=2010-05-08&Action=ListUsers",
        headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      },
      EXAMPLE,
      { region: "us-east-1", service: "iam" },
      AT,
    );
    expect(iam["Authorization"]).toEndWith(
      "SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
  });

  test("the body is part of the signature", async () => {
    const sign = (body: string) =>
      signRequest(
        { method: "POST", url: `${BASE}/x`, body },
        EXAMPLE,
        { region: "us-east-1", service: "route53" },
        AT,
      );
    expect((await sign("a"))["Authorization"]).not.toBe((await sign("b"))["Authorization"]);
  });
});

describe("TXT values", () => {
  test("long values are split into quoted strings of 255 and read back whole", () => {
    const long = dkim("A".repeat(400));
    const value = txtValue(long);
    expect(value.split('" "').length).toBe(2);
    expect(txtText(value)).toBe(long);
    expect(txtValue('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(txtText('"a\\"b\\\\c" "\\073d"')).toBe('a"b\\c;d');
    expect(txtText("v=spf1")).toBe("v=spf1");
  });
});

describe("Route 53", () => {
  test("publishes into the public zone and waits until the change is in sync", async () => {
    const { api, r53, sleeps } = setup();
    const rec = {
      type: "TXT" as const,
      name: "s1._domainkey.mail.example.test",
      content: dkim("B".repeat(300)),
    };
    expect(await r53.upsert(rec)).toEqual({ ok: true, action: "created" });
    const set = api.sets.get("s1._domainkey.mail.example.test.|TXT");
    expect(set?.ttl).toBe(300);
    expect(set?.values.map(txtText)).toEqual([rec.content]);
    expect(sleeps).toEqual([2_000]);
    expect(await r53.upsert(rec)).toEqual({ ok: true, action: "exists" });
    expect(api.posts).toHaveLength(1);
  });

  test("a new DKIM key replaces the old one and keeps other values and the TTL", async () => {
    const { api, r53 } = setup();
    api.sets.set("s1._domainkey.example.test.|TXT", {
      ttl: 60,
      values: [txtValue(dkim("OLD")), '"someone-else"'],
    });
    const r = await r53.upsert({
      type: "TXT",
      name: "s1._domainkey.example.test",
      content: dkim("NEW"),
    });
    expect(r).toEqual({ ok: true, action: "updated" });
    expect(api.sets.get("s1._domainkey.example.test.|TXT")).toEqual({
      ttl: 60,
      values: [txtValue(dkim("NEW")), '"someone-else"'],
    });
  });

  test("removing takes out one value, then the set, then reports it absent", async () => {
    const { api, r53 } = setup();
    const key = "_acme-challenge.mx.example.test.|TXT";
    api.sets.set(key, { ttl: 300, values: ['"token-a"', '"token-b"'] });
    const rec = (content: string) => ({
      type: "TXT" as const,
      name: "_acme-challenge.mx.example.test",
      content,
    });
    expect(await r53.remove(rec("token-a"))).toEqual({ ok: true, action: "removed" });
    expect(api.sets.get(key)?.values).toEqual(['"token-b"']);
    expect(await r53.remove(rec("token-b"))).toEqual({ ok: true, action: "removed" });
    expect(api.sets.has(key)).toBe(false);
    expect(await r53.remove(rec("token-b"))).toEqual({ ok: true, action: "absent" });
  });

  test("MX records carry the priority and a fully qualified host", async () => {
    const { api, r53 } = setup();
    const mx = {
      type: "MX" as const,
      name: "bounce.example.test",
      content: "In.Example.Test",
      priority: 10,
    };
    expect(await r53.upsert(mx)).toEqual({ ok: true, action: "created" });
    expect(api.sets.get("bounce.example.test.|MX")?.values).toEqual(["10 in.example.test."]);
    expect(await r53.upsert({ ...mx, content: "in.example.test." })).toEqual({
      ok: true,
      action: "exists",
    });
    expect(await r53.upsert({ ...mx, priority: 20 })).toEqual({ ok: true, action: "created" });
    expect(await r53.remove(mx)).toEqual({ ok: true, action: "removed" });
    expect(api.sets.get("bounce.example.test.|MX")?.values).toEqual(["20 in.example.test."]);
  });

  test("a change made by someone else in between is kept, not overwritten", async () => {
    const { api, r53, sleeps } = setup();
    const key = "s2._domainkey.example.test.|TXT";
    api.sets.set(key, { ttl: 300, values: ['"first"'] });
    let once = true;
    api.beforeChange = () => {
      if (!once) return;
      once = false;
      api.sets.set(key, { ttl: 300, values: ['"first"', '"theirs"'] });
    };
    const r = await r53.upsert({
      type: "TXT",
      name: "s2._domainkey.example.test",
      content: "ours",
    });
    expect(r).toEqual({ ok: true, action: "created" });
    expect(api.sets.get(key)?.values).toEqual(['"first"', '"theirs"', '"ours"']);
    expect(sleeps[0]).toBe(1_000);
  });

  test("throttling is retried, but not forever", async () => {
    const { api, r53 } = setup();
    const rec = { type: "TXT" as const, name: "s3._domainkey.example.test", content: "x" };
    api.failures.push("Throttling", "PriorRequestNotComplete");
    expect(await r53.upsert(rec)).toEqual({ ok: true, action: "created" });
    api.failures.push("Throttling", "Throttling", "Throttling");
    expect(await r53.remove(rec)).toEqual({ ok: false, error: "Route 53: try again" });
    api.failures.length = 0;
    api.failures.push("AccessDenied");
    expect(await r53.remove(rec)).toEqual({ ok: false, error: "Route 53: try again" });
    expect(api.posts).toHaveLength(1);
  });

  test("no zone, an alias, or a refused signature is an error with the reason", async () => {
    const { api, r53 } = setup();
    expect(await r53.upsert({ type: "TXT", name: "x.nowhere.test", content: "v" })).toEqual({
      ok: false,
      error: "no Route 53 zone for x.nowhere.test",
    });
    api.sets.set("bounce.example.test.|MX", { ttl: 300, values: [], alias: true });
    expect(
      await r53.upsert({ type: "MX", name: "bounce.example.test", content: "in.example.test" }),
    ).toEqual({
      ok: false,
      error: "bounce.example.test MX is an alias or uses a routing policy",
    });
    const wrong = new Route53(
      { ...EXAMPLE, accessKeyId: "OTHER" },
      BASE,
      api.request,
      () => AT,
      async () => {},
    );
    expect(await wrong.upsert({ type: "TXT", name: "a.example.test", content: "v" })).toEqual({
      ok: false,
      error: "Route 53: The request signature is wrong",
    });
  });

  test("two public zones with the same name are refused", async () => {
    const { api, r53 } = setup();
    api.zones.push({ id: "Z9", name: "example.test.", private: false });
    expect(await r53.upsert({ type: "TXT", name: "a.example.test", content: "v" })).toEqual({
      ok: false,
      error: "several public Route 53 zones are named example.test.",
    });
  });
});
