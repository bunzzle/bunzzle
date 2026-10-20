import type { Destination } from "../dns/mx.ts";
import type { DeliveryReport } from "../smtp/deliver.ts";
import type { RecipientResult } from "../smtp/session.ts";

export const SIMULATOR_DOMAIN = "simulator.test";
export const SIMULATOR_SOURCE = "simulator";

export const isSimulator = (address: string) =>
  address.toLowerCase().endsWith(`@${SIMULATOR_DOMAIN}`);

const localPart = (address: string) => address.slice(0, address.lastIndexOf("@")).toLowerCase();

export function simulatorDestination(domain: string): Destination {
  return {
    kind: "targets",
    domain,
    mxHosts: [SIMULATOR_DOMAIN],
    implicit: false,
    authenticated: false,
    targets: [],
    skipped: [],
  };
}

function outcome(address: string, attempt: number): RecipientResult {
  const base = { address, phase: "dot" as const };
  const kind = isSimulator(address) ? localPart(address) : "delivered";
  if (kind === "bounced") {
    return {
      ...base,
      phase: "rcpt",
      status: "bounced",
      code: 550,
      enhanced: "5.1.1",
      reply: "The email account that you tried to reach does not exist (simulated)",
    };
  }
  if (kind === "deferred" && attempt <= 1) {
    return {
      ...base,
      phase: "rcpt",
      status: "deferred",
      code: 451,
      enhanced: "4.2.0",
      reply: "Mailbox busy, please try again later (simulated)",
    };
  }
  return { ...base, status: "delivered", code: 250, enhanced: "2.0.0", reply: "Ok (simulated)" };
}

export function simulate(domain: string, recipients: string[], attempt: number): DeliveryReport {
  return {
    domain,
    destination: simulatorDestination(domain),
    provider: null,
    policy: null,
    sessions: [],
    recipients: recipients.map((r) => outcome(r, attempt)),
  };
}

export const complains = (address: string) =>
  isSimulator(address) && localPart(address) === "complained";

export const suppressedAtIntake = (address: string) =>
  isSimulator(address) && localPart(address) === "suppressed";
