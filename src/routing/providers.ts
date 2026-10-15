export interface Provider {
  id: string;
  name: string;
  tlsRequired: boolean;
}

const TABLE: [suffix: string, provider: Provider][] = [
  ["google.com", { id: "google", name: "Google", tlsRequired: true }],
  ["googlemail.com", { id: "google", name: "Google", tlsRequired: true }],
  ["protection.outlook.com", { id: "microsoft", name: "Microsoft", tlsRequired: true }],
  ["outlook.com", { id: "microsoft", name: "Microsoft", tlsRequired: true }],
  ["yahoodns.net", { id: "yahoo", name: "Yahoo", tlsRequired: true }],
  ["mail.icloud.com", { id: "apple", name: "Apple iCloud", tlsRequired: true }],
  ["protonmail.ch", { id: "proton", name: "Proton", tlsRequired: true }],
  ["messagingengine.com", { id: "fastmail", name: "Fastmail", tlsRequired: true }],
  ["zoho.com", { id: "zoho", name: "Zoho", tlsRequired: true }],
  ["zoho.eu", { id: "zoho", name: "Zoho", tlsRequired: true }],
  ["yandex.net", { id: "yandex", name: "Yandex", tlsRequired: true }],
  ["mail.ru", { id: "mailru", name: "Mail.ru", tlsRequired: true }],
  ["gmx.net", { id: "gmx", name: "GMX / WEB.DE", tlsRequired: true }],
  ["web.de", { id: "gmx", name: "GMX / WEB.DE", tlsRequired: true }],
];

export function providerOf(mxHost: string): Provider | null {
  const host = mxHost.toLowerCase().replace(/\.$/, "");
  for (const [suffix, provider] of TABLE) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return provider;
  }
  return null;
}

export function siteOf(mxHosts: string[]): string {
  return [...new Set(mxHosts.map((h) => h.toLowerCase()))].sort().join(",");
}
