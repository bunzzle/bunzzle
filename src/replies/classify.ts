import type { Phase } from "../smtp/session.ts";
import {
  type CodeRule,
  ENHANCED,
  type Meaning,
  PROVIDER_RULES,
  type Scope,
  TEXT_RULES,
  type TextRule,
} from "./rules.ts";

export type { Scope } from "./rules.ts";

export type Action =
  | "done"
  | "retry"
  | "fail-recipient"
  | "fail-message"
  | "pause-path"
  | "slow-path";

export interface ReplyInput {
  phase: Phase;
  code: number | null;
  enhanced: string | null;
  text: string;
  provider?: string | null;
  shared?: boolean;
}

export interface Classification {
  class: string;
  scope: Scope;
  action: Action;
  permanent: boolean;
  suppress: boolean;
  alert: boolean;
  hintMs: number | null;
  rule: string;
}

const BEFORE_MAIL: ReadonlySet<Phase> = new Set(["connect", "greeting", "ehlo", "starttls"]);

const UNITS: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000 };

export function retryHint(text: string): number | null {
  const m =
    /(?:try|retry|wait|again|after|in)\b[^.\d]{0,30}?(\d{1,5})\s*(seconds?|secs?|s\b|minutes?|mins?|m\b|hours?|hrs?|h\b)/i.exec(
      text,
    );
  if (!m) return null;
  const unit = (m[2] as string)[0]?.toLowerCase() as string;
  return Number(m[1]) * (UNITS[unit] ?? 1_000);
}

function subjectDetail(enhanced: string | null): string | null {
  const m = enhanced ? /^[245]\.(\d{1,3}\.\d{1,3})$/.exec(enhanced) : null;
  return m ? (m[1] as string) : null;
}

function matchText(rules: TextRule[], input: ReplyInput, permanent: boolean): TextRule | null {
  for (const r of rules) {
    if (r.provider && r.provider !== input.provider) continue;
    if (r.when === "temporary" && permanent) continue;
    if (r.when === "permanent" && !permanent) continue;
    if (r.text.test(input.text)) return r;
  }
  return null;
}

function fallback(phase: Phase, permanent: boolean): Meaning {
  if (BEFORE_MAIL.has(phase)) {
    return permanent && (phase === "greeting" || phase === "connect")
      ? { class: "refused-at-greeting", scope: "reputation" }
      : { class: "unavailable", scope: "infrastructure" };
  }
  if (phase === "mail") return { class: "sender-rejected", scope: "sender" };
  if (phase === "rcpt" || phase === "dns") return { class: "rejected", scope: "recipient" };
  return { class: "rejected", scope: "message" };
}

function adjustForPhase(m: Meaning, phase: Phase, permanent: boolean): Meaning {
  if (BEFORE_MAIL.has(phase) && (m.scope === "recipient" || m.scope === "message")) {
    return fallback(phase, permanent);
  }
  if (phase === "mail" && m.scope === "recipient") return { class: m.class, scope: "sender" };
  return m;
}

function actionFor(scope: Scope, permanent: boolean, retry: boolean): Action {
  switch (scope) {
    case "none":
      return "done";
    case "reputation":
      return "pause-path";
    case "rate":
      return "slow-path";
    case "recipient":
      return permanent && !retry ? "fail-recipient" : "retry";
    case "message":
    case "sender":
      return permanent ? "fail-message" : "retry";
    case "infrastructure":
      return "retry";
  }
}

export function classify(input: ReplyInput): Classification {
  const digit = input.code !== null ? Math.floor(input.code / 100) : Number(input.enhanced?.[0]);
  if (digit === 2) {
    return {
      class: "accepted",
      scope: "none",
      action: "done",
      permanent: true,
      suppress: false,
      alert: false,
      hintMs: null,
      rule: "success",
    };
  }
  const permanent = digit === 5;
  const key = subjectDetail(input.enhanced);
  const code: CodeRule | undefined = key ? ENHANCED[key] : undefined;

  let meaning: Meaning;
  let rule: string;
  const provider = matchText(PROVIDER_RULES, input, permanent);
  const text = provider ? null : matchText(TEXT_RULES, input, permanent);
  if (provider) {
    meaning = provider;
    rule = provider.id;
  } else if (text?.strong) {
    meaning = text;
    rule = text.id;
  } else if (code && !code.ambiguous) {
    meaning = code;
    rule = `enhanced ${key}`;
  } else if (text) {
    meaning = text;
    rule = text.id;
  } else if (code) {
    meaning = code;
    rule = `enhanced ${key}`;
  } else {
    meaning = fallback(input.phase, permanent);
    rule = `phase ${input.phase}`;
  }
  meaning = adjustForPhase(meaning, input.phase, permanent);

  const action = actionFor(meaning.scope, permanent, meaning.retry ?? false);
  const suppress =
    action === "fail-recipient" &&
    meaning.scope === "recipient" &&
    (meaning.suppress ?? false) &&
    !input.shared;
  return {
    class: meaning.class,
    scope: meaning.scope,
    action,
    permanent,
    suppress,
    alert: meaning.scope === "reputation" || meaning.scope === "sender",
    hintMs: retryHint(input.text) ?? meaning.hintMs ?? null,
    rule,
  };
}
