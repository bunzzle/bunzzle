import { type Methods, RpcError } from "../ipc/rpc.ts";

export const API_METHODS = [
  "addDomain",
  "addSuppression",
  "authenticate",
  "cancelEmail",
  "checkEmail",
  "createRoute",
  "createTemplate",
  "createWebhook",
  "deleteRoute",
  "deleteTemplate",
  "deleteWebhook",
  "dmarcReports",
  "doctor",
  "enqueue",
  "enqueueBatch",
  "getDomain",
  "getEmail",
  "getTemplate",
  "holds",
  "ips",
  "listDomains",
  "listEmails",
  "listRoutes",
  "listSuppressions",
  "listTemplates",
  "listWebhooks",
  "metrics",
  "paths",
  "queue",
  "releaseHold",
  "removeQueued",
  "removeSuppression",
  "rescheduleEmail",
  "resume",
  "retryRoute",
  "rotateDomain",
  "setDomainPool",
  "setDomainTracking",
  "stats",
  "suspend",
  "tracking",
  "updateTemplate",
  "verifyDomain",
];

export const API_PUBLIC_METHODS = ["health", "trackOpen", "trackClick", "unsubscribe"];

export const INBOUND_METHODS = [
  "inboundRecipient",
  "inboundRoutes",
  "inboundRouted",
  "inboundDmarc",
  "inboundReport",
];

function pick(all: Methods, names: string[]): Methods {
  const out: Methods = {};
  for (const name of names) {
    const m = all[name];
    if (!m) throw new Error(`core has no method ${name}`);
    out[name] = m;
  }
  return out;
}

function withKey(methods: Methods): Methods {
  const out: Methods = {};
  for (const [name, m] of Object.entries(methods)) {
    out[name] = {
      params: m.params,
      handle(params) {
        const hash = (params as { tokenHash?: unknown } | null)?.tokenHash;
        if (typeof hash !== "string") throw new RpcError("unauthenticated", "API key is required");
        return m.handle(params);
      },
    };
  }
  return out;
}

export function apiMethods(all: Methods): Methods {
  return { ...withKey(pick(all, API_METHODS)), ...pick(all, API_PUBLIC_METHODS) };
}

export function inboundMethods(all: Methods): Methods {
  return pick(all, INBOUND_METHODS);
}
