import type { Database } from "bun:sqlite";
import { type ApiKey, allows, keyForHash, type Scope } from "../accounts/api-keys.ts";
import { DEFAULT_PROJECT, type ProjectId } from "../accounts/projects.ts";
import { RpcError } from "../ipc/rpc.ts";

export type Actor =
  | { kind: "project"; project: ProjectId; key: ApiKey }
  | { kind: "operator"; project: ProjectId; key: null };

const OPERATOR: Actor = { kind: "operator", project: DEFAULT_PROJECT, key: null };

const verb = (needed: Scope[]) =>
  needed.length === 1 && needed[0] === "send"
    ? "send email"
    : needed.length === 1 && needed[0] === "read"
      ? "read"
      : "do this";

export function resolveActor(db: Database, hash: string | undefined, ...needed: Scope[]): Actor {
  if (hash === undefined) return OPERATOR;
  const key = keyForHash(db, hash);
  if (!key?.projectId) throw new RpcError("unauthenticated", "API key is invalid");
  if (needed.length > 0 && !needed.some((s) => allows(key.scope, s))) {
    throw new RpcError("forbidden", `this API key cannot ${verb(needed)}`);
  }
  return { kind: "project", project: key.projectId, key };
}
