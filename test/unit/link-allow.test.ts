import { describe, expect, test } from "bun:test";
import { linkHosts, parseAllowed } from "../../src/cli/link-allow.ts";

describe("bunzzle-link allowed addresses", () => {
  test("one entry per node IP, IPv6 without brackets", () => {
    expect(
      linkHosts([
        "198.51.100.8:7466",
        "198.51.100.7:7465",
        "[2001:db8::7]:7465",
        "198.51.100.7:7466",
      ]),
    ).toEqual(["198.51.100.7", "198.51.100.8", "2001:db8::7"]);
  });

  test("reads what systemctl show prints", () => {
    expect(parseAllowed("198.51.100.8/32 2001:db8::7/128 198.51.100.7/32\n")).toEqual([
      "198.51.100.7",
      "198.51.100.8",
      "2001:db8::7",
    ]);
    expect(parseAllowed("\n")).toEqual([]);
  });
});
