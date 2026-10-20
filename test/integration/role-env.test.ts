import { expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { startServe } from "../support/serve.ts";

test.each([
  ["deSEC", { BUNZZLE_DESEC_TOKEN_FILE: "/nonexistent/desec-token" }],
  [
    "Route 53",
    {
      BUNZZLE_ROUTE53_ACCESS_KEY_ID: "AKIDEXAMPLE",
      BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE: "/nonexistent/route53-secret",
    },
  ],
])("under bunzzle serve the dns role reads the %s secret file", async (_name, env) => {
  const started = startServe({ BUNZZLE_MASTER_KEY: generateMasterKey(), ...env });
  await expect(started).rejects.toThrow(/dns/);
});
