import type { OnOutcomes, RecipientResult } from "../smtp/session.ts";

export interface HeldProgress {
  onOutcomes: OnOutcomes;
  flush(): void;
  drop(): void;
}

export function holdProgress(
  send: (recipients: RecipientResult[]) => void,
  holdMs: number,
): HeldProgress {
  let held: RecipientResult[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;
  const drop = () => {
    if (timer) clearTimeout(timer);
    timer = null;
    held = [];
  };
  const flush = () => {
    const out = held;
    drop();
    if (out.length > 0) send(out);
  };
  return {
    onOutcomes: (recipients) => {
      held.push(...recipients);
      timer ??= setTimeout(flush, holdMs);
    },
    flush,
    drop,
  };
}
