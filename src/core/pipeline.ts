import type { Outcome } from "./outcome.ts";

export interface Stage<C> {
  name: string;
  run(ctx: C): Outcome | Promise<Outcome>;
}

export interface PhaseResult {
  outcome: Exclude<Outcome, { kind: "continue" }>;
  stage: string | undefined;
}

export async function runPhase<C>(stages: readonly Stage<C>[], ctx: C): Promise<PhaseResult> {
  for (const stage of stages) {
    let outcome: Outcome;
    try {
      outcome = await stage.run(ctx);
    } catch (err) {
      outcome = { kind: "unknown", reason: `stage threw: ${(err as Error)?.message ?? err}` };
    }
    if (outcome.kind !== "continue") return { outcome, stage: stage.name };
  }
  return { outcome: { kind: "done" }, stage: undefined };
}
