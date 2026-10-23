import type { Database } from "bun:sqlite";

export interface DeliveryNode {
  name: string;
  address: string;
  pin: string;
  notAfter: number;
  ca: string;
  trustedCas: string[];
  createdAt: number;
}

interface Row {
  name: string;
  address: string;
  pin: string;
  not_after: number;
  ca: string;
  trusted_cas: string;
  created_at: number;
}

const fromRow = (r: Row): DeliveryNode => ({
  name: r.name,
  address: r.address,
  pin: r.pin,
  notAfter: r.not_after,
  ca: r.ca,
  trustedCas: JSON.parse(r.trusted_cas) as string[],
  createdAt: r.created_at,
});

export function addNode(db: Database, n: DeliveryNode): boolean {
  return (
    db
      .query<unknown, [string, string, string, number, string, string, number]>(
        `INSERT INTO nodes (name, address, pin, not_after, ca, trusted_cas, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
      )
      .run(n.name, n.address, n.pin, n.notAfter, n.ca, JSON.stringify(n.trustedCas), n.createdAt)
      .changes > 0
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
