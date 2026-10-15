export type Scope =
  | "none"
  | "recipient"
  | "message"
  | "sender"
  | "reputation"
  | "rate"
  | "infrastructure";

export interface Meaning {
  class: string;
  scope: Scope;
  suppress?: boolean;
  retry?: boolean;
  hintMs?: number;
}

export interface CodeRule extends Meaning {
  ambiguous?: boolean;
}

export interface TextRule extends Meaning {
  id: string;
  text: RegExp;
  provider?: string;
  when?: "temporary" | "permanent";
  strong?: boolean;
}

const recipient = (cls: string, suppress = false): CodeRule => ({
  class: cls,
  scope: "recipient",
  suppress,
});
const message = (cls: string): CodeRule => ({ class: cls, scope: "message" });
const sender = (cls: string): CodeRule => ({ class: cls, scope: "sender" });
const infra = (cls: string): CodeRule => ({ class: cls, scope: "infrastructure" });

export const ENHANCED: Record<string, CodeRule> = {
  "0.0": { ...infra("other"), ambiguous: true },
  "1.0": { ...recipient("address-rejected"), ambiguous: true },
  "1.1": recipient("user-unknown", true),
  "1.2": recipient("bad-domain", true),
  "1.3": recipient("bad-address", true),
  "1.4": recipient("ambiguous-address"),
  "1.6": recipient("mailbox-moved", true),
  "1.7": sender("bad-sender-address"),
  "1.8": sender("bad-sender-domain"),
  "1.10": recipient("null-mx", true),
  "2.0": { ...recipient("mailbox-unavailable"), ambiguous: true },
  "2.1": recipient("mailbox-disabled", true),
  "2.2": { ...recipient("mailbox-full"), retry: true },
  "2.3": message("too-big"),
  "2.4": recipient("list-expansion"),
  "3.0": { ...infra("mail-system"), ambiguous: true },
  "3.1": infra("mail-system-full"),
  "3.2": infra("not-accepting"),
  "3.3": message("feature-unsupported"),
  "3.4": message("too-big"),
  "3.5": infra("misconfigured"),
  "4.0": { ...infra("routing"), ambiguous: true },
  "4.1": infra("no-answer"),
  "4.2": infra("bad-connection"),
  "4.3": infra("dns"),
  "4.4": recipient("unroutable"),
  "4.5": { class: "congestion", scope: "rate" },
  "4.6": infra("routing-loop"),
  "4.7": infra("expired"),
  "5.0": { ...infra("protocol"), ambiguous: true },
  "5.1": infra("protocol"),
  "5.2": infra("protocol"),
  "5.3": { class: "too-many-recipients", scope: "rate" },
  "5.4": infra("protocol"),
  "5.5": infra("protocol"),
  "5.6": infra("protocol"),
  "6.0": { ...message("content"), ambiguous: true },
  "6.1": message("media-unsupported"),
  "6.2": message("conversion"),
  "6.3": message("conversion"),
  "6.5": message("conversion"),
  "6.6": message("content-unavailable"),
  "6.7": message("smtputf8-unsupported"),
  "6.8": message("smtputf8-unsupported"),
  "6.9": message("smtputf8-unsupported"),
  "6.10": message("smtputf8-unsupported"),
  "7.0": { ...message("policy"), ambiguous: true },
  "7.1": { ...message("policy"), ambiguous: true },
  "7.2": recipient("list-expansion"),
  "7.3": message("security-conversion"),
  "7.4": message("security-unsupported"),
  "7.5": infra("tls"),
  "7.6": infra("tls"),
  "7.7": message("integrity"),
  "7.8": infra("auth"),
  "7.9": infra("auth"),
  "7.10": infra("tls-required"),
  "7.11": infra("tls-required"),
  "7.13": sender("sender-disabled"),
  "7.14": infra("trust"),
  "7.15": message("priority"),
  "7.16": message("priority"),
  "7.17": recipient("mailbox-owner-changed", true),
  "7.18": recipient("domain-owner-changed", true),
  "7.19": recipient("rrvs"),
  "7.20": sender("dkim"),
  "7.21": sender("dkim"),
  "7.22": sender("dkim"),
  "7.23": sender("spf"),
  "7.24": sender("spf"),
  "7.25": { class: "no-ptr", scope: "reputation" },
  "7.26": sender("auth"),
  "7.27": sender("sender-null-mx"),
  "7.28": { class: "flood", scope: "rate" },
  "7.29": sender("arc"),
  "7.30": infra("tls-required"),
};

export const PROVIDER_RULES: TextRule[] = [
  {
    id: "google.rate",
    provider: "google",
    when: "temporary",
    text: /unusual rate of unsolicited mail|has been temporarily rate limited|4\.7\.28/i,
    class: "rate-limited",
    scope: "rate",
  },
  {
    id: "google.ip-reputation",
    provider: "google",
    when: "permanent",
    text: /unusual rate of unsolicited mail originating from your IP|IP you're using to send mail is not authorized|low reputation of the sending IP/i,
    class: "ip-blocked",
    scope: "reputation",
  },
  {
    id: "google.spam",
    provider: "google",
    text: /likely unsolicited mail|blocked because its content presents a potential security issue|spam/i,
    class: "spam",
    scope: "message",
  },
  {
    id: "google.disabled",
    provider: "google",
    text: /account that you tried to reach is (?:disabled|inactive)/i,
    class: "mailbox-disabled",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "google.unknown",
    provider: "google",
    text: /account that you tried to reach does not exist/i,
    class: "user-unknown",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "google.busy",
    provider: "google",
    text: /receiving mail at a rate that prevents additional messages/i,
    class: "recipient-busy",
    scope: "recipient",
    retry: true,
  },
  {
    id: "google.quota",
    provider: "google",
    text: /over quota|out of storage/i,
    class: "mailbox-full",
    scope: "recipient",
    retry: true,
  },
  {
    id: "microsoft.unknown",
    provider: "microsoft",
    text: /AS\(201806281\)|Recipient address rejected: Access denied|Requested action not taken: mailbox unavailable/i,
    class: "user-unknown",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "microsoft.rate",
    provider: "microsoft",
    text: /rate limited due to IP reputation|4\.7\.65[01]|Server busy|4\.7\.500|\(S775\)|\(S843\)/i,
    class: "rate-limited",
    scope: "rate",
  },
  {
    id: "microsoft.ip-blocked",
    provider: "microsoft",
    text: /part of their network is on our block list|banned sending IP|traffic not accepted from this IP|\(S31[0-9]{2}\)|5\.7\.(?:606|705|708|750)/i,
    class: "ip-blocked",
    scope: "reputation",
  },
  {
    id: "microsoft.auth",
    provider: "microsoft",
    text: /does not meet the required authentication level|5\.7\.(?:509|515)/i,
    class: "auth",
    scope: "sender",
  },
  {
    id: "yahoo.rate",
    provider: "yahoo",
    text: /\[TSS?0[1-4]\]|temporarily deferred due to unexpected volume or user complaints/i,
    class: "rate-limited",
    scope: "rate",
  },
  {
    id: "yahoo.ip-blocked",
    provider: "yahoo",
    text: /\[TSS?0?[59]\]|will be permanently deferred|\[PH01\]/i,
    class: "ip-blocked",
    scope: "reputation",
  },
  {
    id: "yahoo.disabled",
    provider: "yahoo",
    text: /mailbox is disabled|\b554\.30\b/i,
    class: "mailbox-disabled",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "yahoo.unknown",
    provider: "yahoo",
    text: /mailbox not found|user doesn't have a yahoo/i,
    class: "user-unknown",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "apple.policy",
    provider: "apple",
    text: /\[CS01\]|\[HM07\]/i,
    class: "policy",
    scope: "message",
  },
];

export const TEXT_RULES: TextRule[] = [
  {
    id: "greylist",
    strong: true,
    when: "temporary",
    text: /gr[ae]y-?list/i,
    class: "greylisted",
    scope: "infrastructure",
    hintMs: 60_000,
  },
  {
    id: "rate",
    strong: true,
    text: /too many (?:connections|concurrent|messages|mails|emails|recipients|sessions)|connection rate|rate[- ]limit|throttl|slow down|sending too fast|unexpected volume/i,
    class: "rate-limited",
    scope: "rate",
  },
  {
    id: "no-ptr",
    strong: true,
    text: /reverse dns|\bptr\b|\brdns\b|reverse (?:lookup|hostname)|client host .{0,40} unknown|cannot find your (?:reverse )?hostname/i,
    class: "no-ptr",
    scope: "reputation",
  },
  {
    id: "blocklist",
    strong: true,
    text: /blocked using|block ?list|black ?list|spamhaus|spamcop|barracuda|sorbs|\bdnsbl\b|\brbl\b|listed (?:at|on|in) |poor reputation|bad reputation|ip reputation|sender reputation|banned|client host .{0,60} blocked|your ip .{0,40}blocked/i,
    class: "ip-blocked",
    scope: "reputation",
  },
  {
    id: "auth",
    text: /\bdmarc\b|\bspf\b|\bdkim\b|unauthenticated|not authenticated|authentication (?:failed|failure|required|level)/i,
    class: "auth",
    scope: "sender",
  },
  {
    id: "user-unknown",
    text: /user unknown|unknown (?:user|recipient|mailbox)|no such (?:user|mailbox|recipient|address|account)|(?:user|mailbox|address|recipient|account)\b[^.]{0,40}\b(?:does not|doesn't|did not) exist|mailbox (?:unavailable|not found|does not exist)|recipient not found|invalid (?:recipient|mailbox)|unrouteable address|not a valid (?:user|mailbox|recipient)/i,
    class: "user-unknown",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "disabled",
    text: /(?:account|mailbox|user)\b[^.]{0,30}\b(?:disabled|deactivated|suspended|inactive|closed)|no longer (?:active|in use)/i,
    class: "mailbox-disabled",
    scope: "recipient",
    suppress: true,
  },
  {
    id: "mailbox-full",
    text: /over ?quota|quota exceeded|exceeded (?:its|the|their) (?:storage|quota)|mailbox (?:is )?full|insufficient (?:system )?storage|out of storage/i,
    class: "mailbox-full",
    scope: "recipient",
    retry: true,
  },
  {
    id: "relay",
    text: /relay(?:ing)? (?:denied|not permitted|access denied|prohibited)|not permitted to relay|do not relay/i,
    class: "relay-denied",
    scope: "recipient",
  },
  {
    id: "too-big",
    text: /too (?:big|large)|size (?:limit|exceeded)|exceeds (?:the )?(?:maximum|size|message size)/i,
    class: "too-big",
    scope: "message",
  },
  {
    id: "spam",
    text: /spam|unsolicited|\bjunk\b|content (?:rejected|blocked|filter)|virus|malware|phishing|policy reasons/i,
    class: "spam",
    scope: "message",
  },
];
