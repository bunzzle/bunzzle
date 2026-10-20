import { describe, expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import { applyTemplate, prepareEmail, renderTemplate, sendSchema } from "../../src/http/send.ts";
import { MissingVariables, parse, render, TemplateError } from "../../src/templates/render.ts";
import {
  addVersion,
  createTemplate,
  deleteTemplate,
  findTemplate,
  getVersion,
  listTemplates,
  listVersions,
} from "../../src/templates/store.ts";

const html = (source: string, vars: Record<string, unknown> = {}) =>
  render(parse(source), vars, "html");
const text = (source: string, vars: Record<string, unknown> = {}) =>
  render(parse(source), vars, "text");

describe("template rendering", () => {
  test("variables, nested names and numbers", () => {
    expect(
      text("Hi {{ name }}, order {{order.id}} has {{order.count}} items", {
        name: "Ayşe",
        order: { id: "A-1", count: 3 },
      }),
    ).toBe("Hi Ayşe, order A-1 has 3 items");
  });

  test("html escapes values; triple braces do not; text never escapes", () => {
    const vars = { name: `<b>"Tom" & 'Jerry'</b>`, link: "<a href='/x'>x</a>" };
    expect(html("<p>{{name}}</p>{{{link}}}", vars)).toBe(
      "<p>&lt;b&gt;&quot;Tom&quot; &amp; &#39;Jerry&#39;&lt;/b&gt;</p><a href='/x'>x</a>",
    );
    expect(text("{{name}}", vars)).toBe(`<b>"Tom" & 'Jerry'</b>`);
  });

  test("if, else and each", () => {
    const source =
      "{{#if vip}}VIP {{else}}Hi {{/if}}{{name}}:{{#each items}} {{this.sku}}x{{qty}}{{/each}}";
    expect(
      text(source, {
        vip: false,
        name: "Ali",
        items: [
          { sku: "a", qty: 1 },
          { sku: "b", qty: 2 },
        ],
      }),
    ).toBe("Hi Ali: ax1 bx2");
    expect(text("{{#if vip}}VIP{{/if}}", {})).toBe("");
    expect(text("{{#if list}}some{{else}}none{{/if}}", { list: [] })).toBe("none");
    expect(text("{{#each tags}}[{{this}}]{{/each}}", { tags: ["x", "y"] })).toBe("[x][y]");
    expect(text("{{#each tags}}{{name}}{{/each}}", { name: "outer", tags: [1] })).toBe("outer");
  });

  test("every missing variable is reported at once", () => {
    try {
      text("{{a}} {{b.c}} {{a}} {{#each list}}{{/each}}", { b: {} });
      throw new Error("expected missing variables");
    } catch (err) {
      expect(err).toBeInstanceOf(MissingVariables);
      expect((err as MissingVariables).names).toEqual(["a", "b.c", "list"]);
    }
  });

  test("null renders empty; objects and non-lists are refused", () => {
    expect(text("[{{x}}]{{#each y}}!{{/each}}", { x: null, y: null })).toBe("[]");
    expect(() => text("{{x}}", { x: { a: 1 } })).toThrow(TemplateError);
    expect(() => text("{{#each x}}{{/each}}", { x: "abc" })).toThrow("must be a list");
  });

  test("inherited object keys are not variables", () => {
    expect(() => text("{{constructor}}", {})).toThrow(MissingVariables);
    expect(() => text("{{a.toString}}", { a: {} })).toThrow(MissingVariables);
  });

  test("syntax errors name the line", () => {
    expect(() => parse("a\n{{#if x}}")).toThrow("line 2: `{{#if}}` is never closed");
    expect(() => parse("{{/each}}")).toThrow("without an opening block");
    expect(() => parse("{{#if x}}{{/each}}")).toThrow("closes `{{#if}}`");
    expect(() => parse("{{else}}")).toThrow("outside");
    expect(() => parse("{{#if x}}{{else}}{{else}}{{/if}}")).toThrow("outside");
    expect(() => parse("{{#unless x}}{{/unless}}")).toThrow("unknown block");
    expect(() => parse("{{ a b }}")).toThrow("is not a variable name");
    expect(() => parse("{{#if x}}".repeat(11) + "{{/if}}".repeat(11))).toThrow("deeper than 10");
  });

  test("text without tags is kept as it is", () => {
    expect(text("plain { text } with } braces {")).toBe("plain { text } with } braces {");
  });

  test("output is capped", () => {
    const big = "x".repeat(1024 * 1024);
    expect(() =>
      text("{{#each a}}{{#each a}}{{big}}{{/each}}{{/each}}", {
        big,
        a: Array.from({ length: 7 }, () => 1),
      }),
    ).toThrow("larger than");
  });
});

describe("template store", () => {
  test("create, find by id or name, version, delete", () => {
    const db = openDatabase({ path: ":memory:" });
    const t = createTemplate(db, "welcome", { subject: "Hi", html: "<p>Hi</p>", text: null }, 1);
    expect(t?.version).toBe(1);
    expect(createTemplate(db, "welcome", { subject: "x", html: null, text: "x" }, 2)).toBeNull();
    const id = t?.id as string;
    expect(findTemplate(db, "welcome")?.id).toBe(id);
    expect(findTemplate(db, id)?.name).toBe("welcome");
    expect(addVersion(db, id, { subject: "Hello", html: null, text: "Hello" }, 5)).toBe(2);
    expect(findTemplate(db, id)).toMatchObject({ version: 2, updatedAt: 5, createdAt: 1 });
    expect(getVersion(db, id, 1)?.subject).toBe("Hi");
    expect(getVersion(db, id, 2)).toMatchObject({ subject: "Hello", html: null, text: "Hello" });
    expect(getVersion(db, id, 3)).toBeNull();
    expect(listVersions(db, id)).toEqual([1, 2]);
    expect(listTemplates(db).map((x) => x.name)).toEqual(["welcome"]);
    expect(deleteTemplate(db, id, 9)).toBe(true);
    expect(deleteTemplate(db, id, 9)).toBe(false);
    expect(findTemplate(db, "welcome")).toBeNull();
    expect(addVersion(db, id, { subject: "x", html: null, text: "x" }, 10)).toBeNull();
    expect(
      createTemplate(db, "welcome", { subject: "x", html: null, text: "x" }, 11),
    ).not.toBeNull();
  });
});

describe("sending with a template", () => {
  const stored = {
    id: "t1",
    name: "receipt",
    version: 3,
    subject: "Receipt {{order}}",
    html: "<p>Thanks {{name}}</p>",
    text: null,
  };
  const req = (extra: Record<string, unknown>) =>
    sendSchema.parse({ from: "a@acme.test", to: "b@example.test", ...extra });

  test("fills subject and body, escaping html", () => {
    const r = applyTemplate(
      req({ template: { id: "receipt", variables: { order: "#7", name: "<Ali>" } } }),
      stored,
    );
    expect(r).toMatchObject({ subject: "Receipt #7", html: "<p>Thanks &lt;Ali&gt;</p>" });
    expect(r.text).toBeUndefined();
    expect(prepareEmail(r, new Date()).data).toContain("Subject: Receipt #7");
  });

  test("template and own content together are refused", () => {
    expect(() => applyTemplate(req({ template: { id: "receipt" }, subject: "x" }), stored)).toThrow(
      "not both",
    );
  });

  test("missing variables are a 422 naming them", () => {
    try {
      renderTemplate(stored, { order: 1 });
      throw new Error("expected an error");
    } catch (err) {
      expect(err).toMatchObject({ status: 422, message: "Missing template variables: name" });
    }
  });

  test("a line break in a subject variable is refused", () => {
    const r = applyTemplate(
      req({
        template: { id: "receipt", variables: { order: "1\r\nBcc: x@evil.test", name: "a" } },
      }),
      stored,
    );
    expect(() => prepareEmail(r, new Date())).toThrow("line break");
  });

  test("without a template the subject is required", () => {
    expect(() => prepareEmail(req({ text: "x" }), new Date())).toThrow("Missing `subject` field.");
  });
});
