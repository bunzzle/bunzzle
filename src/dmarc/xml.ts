export class XmlError extends Error {}

export interface XmlNode {
  name: string;
  children: XmlNode[];
  text: string;
}

export interface XmlLimits {
  maxDepth: number;
  maxNodes: number;
}

export const XML_LIMITS: XmlLimits = { maxDepth: 32, maxNodes: 200_000 };

const NAMED: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function decode(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(/&([^;\s&<]{1,10});/g, (_, ref: string) => {
    if (ref[0] === "#") {
      const code =
        ref[1] === "x" || ref[1] === "X"
          ? Number.parseInt(ref.slice(2), 16)
          : Number.parseInt(ref.slice(1), 10);
      if (!Number.isInteger(code) || code < 1 || code > 0x10ffff) {
        throw new XmlError(`bad character reference &${ref};`);
      }
      return String.fromCodePoint(code);
    }
    const named = NAMED[ref];
    if (named === undefined) throw new XmlError(`unknown entity &${ref};`);
    return named;
  });
}

function localName(name: string): string {
  const colon = name.indexOf(":");
  return colon < 0 ? name : name.slice(colon + 1);
}

function tagEnd(src: string, from: number): number {
  let quote = "";
  for (let i = from; i < src.length; i++) {
    const ch = src[i];
    if (quote) {
      if (ch === quote) quote = "";
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ">") {
      return i;
    }
  }
  return -1;
}

export function parseXml(src: string, limits: XmlLimits = XML_LIMITS): XmlNode {
  const root: XmlNode = { name: "#document", children: [], text: "" };
  const stack: XmlNode[] = [root];
  let nodes = 0;
  let i = 0;
  const top = () => stack[stack.length - 1] as XmlNode;
  const until = (end: string, from: number) => {
    const at = src.indexOf(end, from);
    if (at < 0) throw new XmlError(`missing ${end}`);
    return at;
  };
  while (i < src.length) {
    const lt = src.indexOf("<", i);
    if (lt < 0) {
      top().text += decode(src.slice(i));
      break;
    }
    if (lt > i) top().text += decode(src.slice(i, lt));
    if (src.startsWith("<?", lt)) {
      i = until("?>", lt + 2) + 2;
      continue;
    }
    if (src.startsWith("<!--", lt)) {
      i = until("-->", lt + 4) + 3;
      continue;
    }
    if (src.startsWith("<![CDATA[", lt)) {
      const end = until("]]>", lt + 9);
      top().text += src.slice(lt + 9, end);
      i = end + 3;
      continue;
    }
    if (src.startsWith("<!", lt)) throw new XmlError("DOCTYPE and declarations are not allowed");
    const gt = tagEnd(src, lt + 1);
    if (gt < 0) throw new XmlError("unclosed tag");
    const tag = src.slice(lt + 1, gt);
    if (tag.startsWith("/")) {
      const name = localName(tag.slice(1).trim());
      if (stack.length === 1 || top().name !== name) throw new XmlError(`unexpected </${name}>`);
      stack.pop();
    } else {
      const raw = /^[^\s/>]+/.exec(tag)?.[0];
      if (!raw) throw new XmlError("tag without a name");
      if (++nodes > limits.maxNodes) throw new XmlError("too many elements");
      const node: XmlNode = { name: localName(raw), children: [], text: "" };
      top().children.push(node);
      if (!tag.endsWith("/")) {
        stack.push(node);
        if (stack.length - 1 > limits.maxDepth) throw new XmlError("elements nested too deep");
      }
    }
    i = gt + 1;
  }
  if (stack.length !== 1) throw new XmlError(`<${top().name}> is not closed`);
  return root;
}

export function child(node: XmlNode | undefined, name: string): XmlNode | undefined {
  return node?.children.find((c) => c.name === name);
}

export function children(node: XmlNode | undefined, name: string): XmlNode[] {
  return node?.children.filter((c) => c.name === name) ?? [];
}

export function textAt(node: XmlNode | undefined, ...path: string[]): string | null {
  let n = node;
  for (const p of path) n = child(n, p);
  const t = n?.text.trim();
  return t ? t : null;
}
