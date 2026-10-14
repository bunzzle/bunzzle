export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

export function manualClock(start = 1_700_000_000_000): Clock & { advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms) {
      t += ms;
    },
  };
}
