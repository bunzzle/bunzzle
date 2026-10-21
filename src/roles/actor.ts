import type { Database } from "bun:sqlite";
import { type ApiKey, allows, keyForHash, type Scope } from "../accounts/api-keys.ts";
import {
  DEFAULT_PROJECT,
  findProject,
  liveProjects,
  type ProjectId,
} from "../accounts/projects.ts";
import { RpcError } from "../ipc/rpc.ts";

export interface Auth {
  tokenHash?: string | undefined;
  project?: string | undefined;
}

export type Actor =
  | { kind: "project"; project: ProjectId; key: ApiKey }
  | { kind: "operator"; project: ProjectId; key: null };

export type Caller = Actor | { kind: "admin"; project: null; key: ApiKey };

const verb = (needed: Scope[]) =>
  needed.length === 1 && needed[0] === "send"
    ? "send email"
    : needed.length === 1 && needed[0] === "read"
      ? "read"
      : "do this";

function operatorProject(db: Database, name: string | undefined): ProjectId {
  if (name === undefined) return DEFAULT_PROJECT;
  const p = findProject(db, name);
  if (!p) throw new RpcError("not-found", `no project ${name}`);
  return p.id;
}

function lookup(db: Database, auth: Auth, needed: Scope[]): Caller {
  if (auth.tokenHash === undefined) {
    return { kind: "operator", project: operatorProject(db, auth.project), key: null };
  }
  if (auth.project !== undefined) {
    throw new RpcError("forbidden", "an API key always works on its own project");
  }
  const key = keyForHash(db, auth.tokenHash);
  if (!key) throw new RpcError("unauthenticated", "API key is invalid");
  if (key.scope === "admin") return { kind: "admin", project: null, key };
  if (!key.projectId) throw new RpcError("unauthenticated", "API key is invalid");
  if (needed.length > 0 && !needed.some((s) => allows(key.scope, s))) {
    throw new RpcError("forbidden", `this API key cannot ${verb(needed)}`);
  }
  return { kind: "project", project: key.projectId, key };
}

export function resolveActor(db: Database, auth: Auth, ...needed: Scope[]): Actor {
  const c = lookup(db, auth, needed);
  if (c.kind === "admin") {
    throw new RpcError("forbidden", "admin keys manage projects; use a project key for this");
  }
  return c;
}

export function resolveServer(db: Database, auth: Auth, ...needed: Scope[]): Caller {
  return lookup(db, auth, needed);
}

export function resolveAdmin(db: Database, auth: Auth): Caller {
  const c = lookup(db, { tokenHash: auth.tokenHash }, []);
  if (c.kind === "project") throw new RpcError("forbidden", "this needs an admin key");
  return c;
}

export const scopeOf = (c: Caller): ProjectId | null => (c.kind === "project" ? c.project : null);

export const actorName = (c: Caller): string => (c.key ? `key:${c.key.id}` : "operator");

export function requireServerWide(db: Database, c: Caller): void {
  if (c.kind !== "project") return;
  if (liveProjects(db) > 1) {
    throw new RpcError(
      "forbidden",
      "this changes delivery for every project; the operator must do it",
    );
  }
}
