export interface Limits {
  connections: number;
  ratePerSec: number;
  perConnection: number;
}

export const DEFAULT_LIMITS: Limits = { connections: 5, ratePerSec: 5, perConnection: 100 };

const BY_PROVIDER: Record<string, Limits> = {
  google: { connections: 10, ratePerSec: 20, perConnection: 100 },
  microsoft: { connections: 5, ratePerSec: 10, perConnection: 100 },
  yahoo: { connections: 5, ratePerSec: 5, perConnection: 20 },
  apple: { connections: 5, ratePerSec: 5, perConnection: 50 },
  proton: { connections: 5, ratePerSec: 5, perConnection: 50 },
  fastmail: { connections: 5, ratePerSec: 5, perConnection: 50 },
  zoho: { connections: 5, ratePerSec: 5, perConnection: 50 },
  yandex: { connections: 3, ratePerSec: 3, perConnection: 50 },
  mailru: { connections: 3, ratePerSec: 3, perConnection: 50 },
  gmx: { connections: 3, ratePerSec: 3, perConnection: 50 },
};

export function limitsFor(provider: string | null): Limits {
  return (provider ? BY_PROVIDER[provider] : undefined) ?? DEFAULT_LIMITS;
}
