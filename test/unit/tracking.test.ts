import { describe, expect, test } from "bun:test";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { encodeUrl } from "../../src/http/track.ts";
import { makeToken, readToken } from "../../src/signer/tokens.ts";
import { decodeEntities, MAX_LINKS, rewriteHtml, trackableLinks } from "../../src/tracking/html.ts";
import { checkTracking, type Tracking } from "../../src/tracking/store.ts";

const master = await masterKeyFrom(generateMasterKey());
const ID = "01a13f75-7780-77d7-b8a2-1429340b86fe";

describe("html links", () => {
  test("finds http and https hrefs in any quoting, decodes entities, keeps order, no duplicates", () => {
    const html = `<p><a href="https://a.example/x?a=1&amp;b=2">A</a>
      <A HREF='http://b.example/'>B</A> <a href=https://c.example/c>C</a>
      <a href="https://a.example/x?a=1&b=2">again</a>`;
    expect(trackableLinks(html)).toEqual([
      "https://a.example/x?a=1&b=2",
      "http://b.example/",
      "https://c.example/c",
    ]);
  });

  test("skips mailto, anchors, relative links, link and base tags, scripts and data-no-track", () => {
    const html = `<link href="https://css.example/a.css"><base href="https://base.example/">
      <a href="mailto:a@example.com">m</a><a href="#top">t</a><a href="/path">p</a>
      <a data-no-track href="https://reset.example/token">r</a>
      <script>var s = '<a href="https://script.example/">';</script>
      <a href="javascript:alert(1)">j</a><a href="https://keep.example/">k</a>`;
    expect(trackableLinks(html)).toEqual(["https://keep.example/"]);
  });

  test("tracks VML buttons inside Outlook conditional comments", () => {
    const html = `<!--[if mso]><v:roundrect href="https://button.example/go"></v:roundrect><![endif]-->`;
    expect(trackableLinks(html)).toEqual(["https://button.example/go"]);
  });

  test("caps the number of links", () => {
    const html = Array.from(
      { length: MAX_LINKS + 20 },
      (_, i) => `<a href="https://x.example/${i}">`,
    ).join("");
    expect(trackableLinks(html)).toHaveLength(MAX_LINKS);
  });

  test("rewrites only the hrefs it is given and adds the pixel before </body>", () => {
    const html = `<html><body><a class="b" href="https://a.example/?q=1&amp;r=2">A</a><a href="https://skip.example/">S</a></BODY></html>`;
    const out = rewriteHtml(
      html,
      (url) => (url === "https://a.example/?q=1&r=2" ? "https://t.example/c/x" : null),
      "https://t.example/o/y",
    );
    expect(out).toBe(
      `<html><body><a class="b" href="https://t.example/c/x">A</a><a href="https://skip.example/">S</a><img src="https://t.example/o/y" width="1" height="1" alt="" style="width:1px;height:1px;border:0"></BODY></html>`,
    );
    expect(rewriteHtml("<p>hi</p>", () => null, "https://t.example/o/y")).toEndWith(
      `<img src="https://t.example/o/y" width="1" height="1" alt="" style="width:1px;height:1px;border:0">`,
    );
    expect(rewriteHtml("<p>hi</p>", () => null, null)).toBe("<p>hi</p>");
  });

  test("broken markup does not throw", () => {
    for (const html of ["<a href=", "<a href='https://x.example/", "<", "<<a", '<a href="">']) {
      expect(() => rewriteHtml(html, () => "x", null)).not.toThrow();
    }
  });

  test("entities", () => {
    expect(decodeEntities("a&amp;b&#38;c&#x26;d&quot;&unknown;")).toBe('a&b&c&d"&unknown;');
  });
});

describe("link and open tokens", () => {
  test("a link token is bound to its url", async () => {
    const t = await makeToken(master, "c", ID, "https://a.example/");
    expect(await readToken(master, t, "https://a.example/")).toEqual({
      purpose: "c",
      messageId: ID,
    });
    expect(await readToken(master, t, "https://evil.example/")).toBeNull();
    expect(await readToken(master, t)).toBeNull();
  });

  test("an open token cannot be used as a link token or the other way round", async () => {
    const o = await makeToken(master, "o", ID);
    expect(await readToken(master, o)).toEqual({ purpose: "o", messageId: ID });
    expect(await readToken(master, o, "https://a.example/")).toBeNull();
    const u = await makeToken(master, "u", ID);
    expect(await readToken(master, u, "https://a.example/")).toBeNull();
    await expect(makeToken(master, "o", ID, "https://a.example/")).rejects.toThrow();
    await expect(makeToken(master, "c", ID)).rejects.toThrow();
  });

  test("urls travel as base64url in the path", () => {
    const url = "https://a.example/ş?x=1&y=/+";
    const enc = encodeUrl(url);
    expect(enc).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(new TextDecoder().decode(Uint8Array.fromBase64(enc, { alphabet: "base64url" }))).toBe(
      url,
    );
  });
});

describe("tracking host check", () => {
  const t: Tracking = {
    host: "links.example.com",
    opens: true,
    clicks: true,
    status: "pending",
    found: null,
    checkedAt: null,
  };

  test("verified only when the CNAME points at the public host", () => {
    expect(checkTracking(t, ["Mail.Example.net."], "mail.example.net", 5)).toMatchObject({
      status: "verified",
      found: "mail.example.net",
      checkedAt: 5,
    });
    expect(checkTracking(t, [], "mail.example.net", 5).status).toBe("missing");
    expect(checkTracking(t, ["other.example."], "mail.example.net", 5).status).toBe("mismatch");
  });
});
