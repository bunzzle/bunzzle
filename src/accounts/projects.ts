import type { Database } from "bun:sqlite";

declare const brand: unique symbol;

export type ProjectId = string & { readonly [brand]: "ProjectId" };

export const DEFAULT_PROJECT = "default" as ProjectId;

export function projectOfMessage(db: Database, messageId: string): ProjectId | null {
  return (
    (db
      .query<{ project_id: string }, [string]>("SELECT project_id FROM messages WHERE id = ?")
      .get(messageId)?.project_id as ProjectId | undefined) ?? null
  );
}
