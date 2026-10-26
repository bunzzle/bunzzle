import { tags } from "./domains.ts";

export const bimiName = (domain: string) => `default._bimi.${domain}`;

export interface BimiCheck {
  status: "ok" | "warn" | "fail";
  detail: string;
}

const https = (url: string) => /^https:\/\/[^\s/]+/i.test(url);

export function dmarcEnforced(dmarc: string | null): boolean {
  if (!dmarc || !/^v=DMARC1\b/i.test(dmarc.trim())) return false;
  const t = tags(dmarc);
  const p = (t.get("p") ?? "").toLowerCase();
  const sp = (t.get("sp") ?? p).toLowerCase();
  const pct = t.get("pct");
  return (
    (p === "quarantine" || p === "reject") &&
    sp !== "none" &&
    (pct === undefined || Number(pct) === 100)
  );
}

export function bimiCheck(found: string[], dmarc: string | null): BimiCheck | null {
  const records = found.filter((t) => /^v=BIMI1\s*(;|$)/i.test(t.trim()));
  if (records.length === 0) return null;
  if (records.length > 1) {
    return {
      status: "fail",
      detail: `${records.length} BIMI records are published: receivers ignore all of them`,
    };
  }
  const t = tags(records[0] as string);
  const logo = t.get("l") ?? "";
  const mark = t.get("a") ?? "";
  if (!logo && !mark) return { status: "ok", detail: "the record declines BIMI: no logo is shown" };
  if (logo && !https(logo)) {
    return { status: "fail", detail: `the logo l=${logo} is not an https URL` };
  }
  if (mark && !https(mark)) {
    return { status: "fail", detail: `the mark certificate a=${mark} is not an https URL` };
  }
  if (!dmarcEnforced(dmarc)) {
    return {
      status: "fail",
      detail: `no logo is shown until DMARC is p=quarantine or p=reject for all mail: found ${dmarc ? `"${dmarc}"` : "no DMARC record"}`,
    };
  }
  if (!mark) {
    return {
      status: "warn",
      detail: `logo ${logo}; no mark certificate (a=): most mailbox providers show the logo only with one`,
    };
  }
  return { status: "ok", detail: `${logo ? `logo ${logo}, ` : ""}mark certificate ${mark}` };
}
