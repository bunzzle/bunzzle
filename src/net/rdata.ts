import type { CfRecord } from "./cloudflare.ts";

export const fqdn = (name: string) => `${name.toLowerCase().replace(/\.$/, "")}.`;

export function txtValue(content: string): string {
  const parts: string[] = [];
  for (let i = 0; i < content.length || i === 0; i += 255) {
    parts.push(`"${content.slice(i, i + 255).replace(/[\\"]/g, (c) => `\\${c}`)}"`);
  }
  return parts.join(" ");
}

export function txtText(value: string): string {
  const parts = [...value.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1] as string);
  const raw = parts.length > 0 ? parts.join("") : value;
  return raw.replace(/\\([0-7]{3}|.)/g, (_, e: string) =>
    e.length === 3 ? String.fromCharCode(Number.parseInt(e, 8)) : e,
  );
}

export const mxValue = (rec: CfRecord) => `${rec.priority ?? 10} ${fqdn(rec.content)}`;

export const recordValue = (rec: CfRecord) =>
  rec.type === "MX" ? mxValue(rec) : txtValue(rec.content);

export function sameValue(rec: CfRecord, value: string): boolean {
  if (rec.type === "TXT") return txtText(value) === rec.content;
  const [priority, host] = value.trim().split(/\s+/);
  return Number(priority) === (rec.priority ?? 10) && fqdn(host ?? "") === fqdn(rec.content);
}

export function ownedKind(rec: CfRecord): string | null {
  if (rec.type !== "TXT") return null;
  if (rec.content.startsWith("v=spf1")) return "v=spf1";
  if (rec.content.startsWith("v=DKIM1")) return "v=DKIM1";
  return null;
}

export type Plan = {
  values: string[] | null;
  action: "created" | "updated" | "exists" | "removed" | "absent";
};

export function planUpsert(rec: CfRecord, values: string[]): Plan {
  if (values.some((v) => sameValue(rec, v))) return { values: null, action: "exists" };
  const wanted = recordValue(rec);
  const kind = ownedKind(rec);
  const i = kind ? values.findIndex((v) => txtText(v).startsWith(kind)) : -1;
  if (i >= 0) return { values: values.map((v, j) => (j === i ? wanted : v)), action: "updated" };
  return { values: [...values, wanted], action: "created" };
}

export function planRemove(rec: CfRecord, values: string[]): Plan {
  const rest = values.filter((v) => !sameValue(rec, v));
  return rest.length === values.length
    ? { values: null, action: "absent" }
    : { values: rest, action: "removed" };
}
