import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import type { Writer } from "../core/store/writer.ts";
import { type Methods, method, RpcError } from "../ipc/rpc.ts";
import { parse, TemplateError } from "../templates/render.ts";
import {
  addVersion,
  type Content,
  createTemplate,
  deleteTemplate,
  findTemplate,
  getVersion,
  listTemplates,
  listVersions,
  type TemplateInfo,
} from "../templates/store.ts";
import { b } from "../validate/schema.ts";
import { resolveActor } from "./actor.ts";
import { tokenHash } from "./wire.ts";

export interface TemplateDeps {
  db: Database;
  writer: Writer;
  now?: () => number;
}

export const TEMPLATE_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BODY = 2 * 1024 * 1024;

const ref = b.string().min(1).max(64);
const subject = b.string().min(1).max(998);
const body = b.string().max(MAX_BODY);

const summary = (t: TemplateInfo) => ({
  object: "template",
  id: t.id,
  name: t.name,
  version: t.version,
  created_at: new Date(t.createdAt).toISOString(),
  updated_at: new Date(t.updatedAt).toISOString(),
});

function check(c: Content): Content {
  if (c.html === null && c.text === null)
    throw new RpcError("invalid", "a template needs html or text");
  for (const field of ["subject", "html", "text"] as const) {
    const source = c[field];
    if (source === null) continue;
    try {
      parse(source);
    } catch (err) {
      if (err instanceof TemplateError) throw new RpcError("invalid", `${field}: ${err.message}`);
      throw err;
    }
  }
  return c;
}

export function templateMethods(deps: TemplateDeps): Methods {
  const { db, writer } = deps;
  const now = deps.now ?? Date.now;

  const find = (project: ProjectId, id: string) => {
    const t = findTemplate(db, project, id);
    if (!t) throw new RpcError("not-found", "template not found");
    return t;
  };

  return {
    createTemplate: method(
      b.object({
        tokenHash,
        name: b.string().max(64),
        subject,
        html: body.optional(),
        text: body.optional(),
      }),
      async (p) => {
        const { project } = resolveActor(db, p.tokenHash, "full");
        if (!TEMPLATE_NAME.test(p.name) || UUID.test(p.name)) {
          throw new RpcError(
            "invalid",
            "name must be 1 to 64 lowercase letters, digits, _ and -, starting with a letter or digit",
          );
        }
        const content = check({ subject: p.subject, html: p.html ?? null, text: p.text ?? null });
        const t = await writer.run((d) => createTemplate(d, project, p.name, content, now()));
        if (!t) throw new RpcError("invalid", `a template named ${p.name} already exists`);
        return { ...summary(t), ...content, versions: [1] };
      },
    ),

    listTemplates: method(b.object({ tokenHash }), (p) => {
      const { project } = resolveActor(db, p.tokenHash, "read");
      return listTemplates(db, project).map(summary);
    }),

    getTemplate: method(
      b.object({ tokenHash, id: ref, version: b.number().int().min(1).optional() }),
      (p) => {
        const { project } = resolveActor(db, p.tokenHash, "read", "send");
        const t = find(project, p.id);
        const v = getVersion(db, t.id, p.version ?? t.version);
        if (!v) throw new RpcError("not-found", `template ${t.name} has no version ${p.version}`);
        return {
          ...summary(t),
          version: v.version,
          subject: v.subject,
          html: v.html,
          text: v.text,
          versions: listVersions(db, t.id),
        };
      },
    ),

    updateTemplate: method(
      b.object({
        tokenHash,
        id: ref,
        subject: subject.optional(),
        html: body.nullable().optional(),
        text: body.nullable().optional(),
      }),
      async (p) => {
        const { project } = resolveActor(db, p.tokenHash, "full");
        const t = find(project, p.id);
        const latest = getVersion(db, t.id, t.version) as Content;
        const content = check({
          subject: p.subject ?? latest.subject,
          html: p.html === undefined ? latest.html : p.html,
          text: p.text === undefined ? latest.text : p.text,
        });
        const v = await writer.run((d) => addVersion(d, project, t.id, content, now()));
        if (v === null) throw new RpcError("not-found", "template not found");
        return {
          ...summary({ ...t, version: v, updatedAt: now() }),
          ...content,
          versions: listVersions(db, t.id),
        };
      },
    ),

    deleteTemplate: method(b.object({ tokenHash, id: ref }), async (p) => {
      const { project } = resolveActor(db, p.tokenHash, "full");
      const t = find(project, p.id);
      if (!(await writer.run((d) => deleteTemplate(d, project, t.id, now())))) {
        throw new RpcError("not-found", "template not found");
      }
      return { id: t.id, deleted: true };
    }),
  };
}
