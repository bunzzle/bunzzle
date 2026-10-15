import { splitMessage } from "../dkim/canonicalize.ts";
import { AddressError, domainOf, parseAddress } from "./address.ts";

export function senderDomainOf(raw: string): string {
  const from = splitMessage(raw).headers.filter((h) => h.name.trim().toLowerCase() === "from");
  if (from.length !== 1) throw new AddressError("the message needs exactly one From header");
  const value = (from[0] as { raw: string }).raw.replace(/\r\n[ \t]+/g, " ");
  try {
    return domainOf(parseAddress(value.slice(value.indexOf(":") + 1)).address);
  } catch {
    throw new AddressError("the From header has no valid address");
  }
}
