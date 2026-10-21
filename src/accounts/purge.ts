import type { Database } from "bun:sqlite";

export interface Purged {
  project: string | null;
  messages: number;
  finished: boolean;
}

const MESSAGE_CHILDREN = [
  "DELETE FROM recipients WHERE job_id IN (SELECT id FROM jobs WHERE message_id IN (SELECT value FROM json_each(?)))",
  "DELETE FROM jobs WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM events WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM bodies WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM email_tags WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM email_index WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM idempotency WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM conversations WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM inbound WHERE message_id IN (SELECT value FROM json_each(?))",
  "DELETE FROM messages WHERE id IN (SELECT value FROM json_each(?))",
];

const PROJECT_ROWS = [
  "DELETE FROM holds WHERE target IN (SELECT 'key:' || id FROM api_keys WHERE project_id = ?)",
  "DELETE FROM api_keys WHERE project_id = ?",
  "DELETE FROM webhook_deliveries WHERE webhook_id IN (SELECT id FROM webhooks WHERE project_id = ?)",
  "DELETE FROM webhooks WHERE project_id = ?",
  "DELETE FROM route_deliveries WHERE route_id IN (SELECT id FROM routes WHERE project_id = ?)",
  "DELETE FROM routes WHERE project_id = ?",
  "DELETE FROM template_versions WHERE template_id IN (SELECT id FROM templates WHERE project_id = ?)",
  "DELETE FROM templates WHERE project_id = ?",
  "DELETE FROM suppressions WHERE project_id = ?",
  "DELETE FROM stats_daily WHERE project_id = ?",
  "DELETE FROM domains WHERE project_id = ?",
  "DELETE FROM projects WHERE id = ?",
];

export function purgeDeletedProject(db: Database, limit = 500): Purged {
  const deleted = db
    .query<{ id: string }, []>(
      "SELECT id FROM projects WHERE deleted_at IS NOT NULL ORDER BY deleted_at",
    )
    .all()
    .map((r) => r.id);
  for (const project of deleted) {
    const ids = db
      .query<{ id: string }, [string, number]>(
        `SELECT m.id FROM messages m
         WHERE m.project_id = ?
           AND NOT EXISTS (
             SELECT 1 FROM jobs j WHERE j.message_id = m.id AND j.state IN ('leased', 'unknown')
           )
         LIMIT ?`,
      )
      .all(project, limit)
      .map((r) => r.id);
    if (ids.length > 0) {
      const list = JSON.stringify(ids);
      for (const sql of MESSAGE_CHILDREN) db.query<unknown, [string]>(sql).run(list);
      return { project, messages: ids.length, finished: false };
    }
    const left = db
      .query<{ n: number }, [string]>("SELECT 1 AS n FROM messages WHERE project_id = ? LIMIT 1")
      .get(project);
    if (left) continue;
    for (const sql of PROJECT_ROWS) db.query<unknown, [string]>(sql).run(project);
    return { project, messages: 0, finished: true };
  }
  return { project: null, messages: 0, finished: false };
}
