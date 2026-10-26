import { splitMessage } from "../dkim/canonicalize.ts";
import { AddressError, soleAddressDomain } from "./address.ts";

export function senderDomainOf(raw: string): string {
  const from = splitMessage(raw).headers.filter((h) => h.name.trim().toLowerCase() === "from");
  if (from.length !== 1) throw new AddressError("the message needs exactly one From header");
  const value = (from[0] as { raw: string }).raw;
  try {
    return soleAddressDomain(value.slice(value.indexOf(":") + 1));
  } catch {
    throw new AddressError("the From header has no valid address");
  }
}
