import { type Methods, RpcError } from "../ipc/rpc.ts";

export const API_METHODS = [
  "addDomain",
  "addSuppression",
  "authenticate",
  "cancelEmail",
  "checkEmail",
  "createProject",
  "createPoolRule",
  "createProjectKey",
  "createRoute",
  "createTemplate",
  "createWebhook",
  "deleteProject",
  "deleteRoute",
  "deleteTemplate",
  "deletePoolRule",
  "deleteWebhook",
  "dmarcReports",
  "doctor",
  "enqueue",
  "enqueueBatch",
  "getDomain",
  "getEmail",
  "getProject",
  "getTemplate",
  "holds",
  "ips",
  "listDomains",
  "listEmails",
  "listPoolRules",
  "listProjects",
  "listRoutes",
  "listSuppressions",
  "listTemplates",
  "getWebhookResend",
  "listWebhookDeliveries",
  "listWebhooks",
  "metrics",
  "paths",
  "queue",
  "releaseHold",
  "removeQueued",
  "removeSuppression",
  "rescheduleEmail",
  "resendWebhookDelivery",
  "resendWebhookRange",
  "resume",
  "retryRoute",
  "rotateDomain",
  "setDomainMode",
  "setDomainPool",
  "setDomainTracking",
  "stats",
  "suspend",
  "tracking",
  "updateProject",
  "updateTemplate",
  "verifyDomain",
];

export const API_PUBLIC_METHODS = ["health", "trackOpen", "trackClick", "unsubscribe"];

export const INBOUND_METHODS = [
  "inboundRecipient",
  "inboundRoutes",
  "inboundRouted",
  "inboundScan",
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
        const p = params as { tokenHash?: unknown; project?: unknown } | null;
        if (typeof p?.tokenHash !== "string") {
          throw new RpcError("unauthenticated", "API key is required");
        }
        if (p.project !== undefined) {
          throw new RpcError("forbidden", "an API key always works on its own project");
        }
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
