import type { Database } from "bun:sqlite";

export type NodeKind = "delivery" | "egress";

export interface DeliveryNode {
  name: string;
  kind: NodeKind;
  address: string;
  pin: string;
  notAfter: number;
  ca: string;
  trustedCas: string[];
  corePins: string[];
  createdAt: number;
}

interface Row {
  name: string;
  kind: NodeKind;
  address: string;
  pin: string;
  not_after: number;
  ca: string;
  trusted_cas: string;
  core_pins: string;
  created_at: number;
}

const fromRow = (r: Row): DeliveryNode => ({
  name: r.name,
  kind: r.kind,
  address: r.address,
  pin: r.pin,
  notAfter: r.not_after,
  ca: r.ca,
  trustedCas: JSON.parse(r.trusted_cas) as string[],
  corePins: JSON.parse(r.core_pins) as string[],
  createdAt: r.created_at,
});

export function addNode(db: Database, n: DeliveryNode): boolean {
  return (
    db
      .query<unknown, [string, NodeKind, string, string, number, string, string, string, number]>(
        `INSERT INTO nodes (name, kind, address, pin, not_after, ca, trusted_cas, core_pins, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
      )
      .run(
        n.name,
        n.kind,
        n.address,
        n.pin,
        n.notAfter,
        n.ca,
        JSON.stringify(n.trustedCas),
        JSON.stringify(n.corePins),
        n.createdAt,
      ).changes > 0
  );
}

export function listNodes(db: Database): DeliveryNode[] {
  return db.query<Row, []>("SELECT * FROM nodes ORDER BY name").all().map(fromRow);
}

export function getNode(db: Database, name: string): DeliveryNode | null {
  const r = db.query<Row, [string]>("SELECT * FROM nodes WHERE name = ?").get(name);
  return r ? fromRow(r) : null;
}

export function removeNode(db: Database, name: string): boolean {
  return db.query<unknown, [string]>("DELETE FROM nodes WHERE name = ?").run(name).changes > 0;
}

export function updateNode(
  db: Database,
  name: string,
  n: Pick<DeliveryNode, "pin" | "notAfter" | "ca" | "trustedCas" | "corePins">,
): boolean {
  return (
    db
      .query<unknown, [string, number, string, string, string, string]>(
        `UPDATE nodes SET pin = ?, not_after = ?, ca = ?, trusted_cas = ?, core_pins = ?
         WHERE name = ?`,
      )
      .run(n.pin, n.notAfter, n.ca, JSON.stringify(n.trustedCas), JSON.stringify(n.corePins), name)
      .changes > 0
  );
}
