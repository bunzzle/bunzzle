import { describe, expect, test } from "bun:test";
import { DmarcError, readDmarcReport, reportFromXml } from "../../src/dmarc/report.ts";
import { parseXml, textAt, XmlError } from "../../src/dmarc/xml.ts";
import { REPORT, reportMail, zip } from "../support/dmarc.ts";

const enc = new TextEncoder();

describe("XML", () => {
  test("elements, namespaces, entities, CDATA and comments", () => {
    const doc = parseXml(
      `<?xml version="1.0"?><!-- c --><a:x xmlns:a="u"><a:y q='>'>1 &amp; 2 &#x41;</a:y><z><![CDATA[<raw>]]></z><e/></a:x>`,
    );
    expect(textAt(doc, "x", "y")).toBe("1 & 2 A");
    expect(textAt(doc, "x", "z")).toBe("<raw>");
  });

  test("DOCTYPE, unknown entities, bad nesting and depth are refused", () => {
    expect(() => parseXml('<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')).toThrow(XmlError);
    expect(() => parseXml("<x>&nope;</x>")).toThrow(XmlError);
    expect(() => parseXml("<x><y></x></y>")).toThrow(XmlError);
    expect(() => parseXml("<x>")).toThrow(XmlError);
    expect(() => parseXml(`${"<a>".repeat(40)}${"</a>".repeat(40)}`)).toThrow("too deep");
  });
});

describe("DMARC aggregate reports", () => {
  test("rows, alignment and passing domains", () => {
    const r = reportFromXml(REPORT);
    expect(r.org).toBe("mail.example");
    expect(r.domain).toBe("acme.test");
    expect(r.begin).toBe(1729296000_000);
    expect(r.rows).toEqual([
      {
        sourceIp: "203.0.113.5",
        count: 42,
        disposition: "none",
        dkim: "pass",
        spf: "pass",
        headerFrom: "acme.test",
        envelopeFrom: "bounce.acme.test",
        dkimDomains: ["acme.test"],
        spfDomain: "bounce.acme.test",
      },
      {
        sourceIp: "198.51.100.7",
        count: 3,
        disposition: "none",
        dkim: "fail",
        spf: "fail",
        headerFrom: "acme.test",
        envelopeFrom: null,
        dkimDomains: [],
        spfDomain: null,
      },
    ]);
  });

  test("zip, gzip and plain XML attachments", async () => {
    const xml = enc.encode(REPORT);
    for (const mail of [
      reportMail("application/zip", "mail.example!acme.test!1!2.zip", zip("r.xml", xml)),
      reportMail("application/gzip", "r.xml.gz", Bun.gzipSync(xml)),
      reportMail("application/octet-stream", "r.xml", xml),
    ]) {
      expect((await readDmarcReport(mail)).rows.length).toBe(2);
    }
  });

  test("a compression bomb is stopped while unpacking", async () => {
    const bomb = Bun.gzipSync(new Uint8Array(30 * 1024 * 1024));
    const started = performance.now();
    await expect(readDmarcReport(reportMail("application/gzip", "r.xml.gz", bomb))).rejects.toThrow(
      "too large",
    );
    expect(performance.now() - started).toBeLessThan(2_000);
    const zipBomb = zip("r.xml", new Uint8Array(30 * 1024 * 1024));
    await expect(readDmarcReport(reportMail("application/zip", "r.zip", zipBomb))).rejects.toThrow(
      "too large",
    );
  });

  test("broken input is a DmarcError", async () => {
    await expect(readDmarcReport("Subject: x\r\n\r\nno attachment")).rejects.toThrow(DmarcError);
    await expect(
      readDmarcReport(reportMail("application/zip", "r.zip", enc.encode("not a zip at all"))),
    ).rejects.toThrow(DmarcError);
    expect(() => reportFromXml("<feedback><report_metadata/></feedback>")).toThrow(DmarcError);
  });
});
